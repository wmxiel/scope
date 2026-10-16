open Model

type entry = Absent | Invalid of string | Table of Address.Physical.t | Leaf of int * Address.Physical.t

let shift level = 12 + (9 * (level - 1))
let span level = Int64.shift_left 1L (shift level)

let decode features ~nxe ~level raw =
  let open Address in
  if not (bit raw 0) then Absent
  else if bit raw 63 && not nxe then Invalid "nx bit with nxe disabled"
  else if Int64.logand raw (Int64.logand (mask 52) (Int64.lognot (mask features.phys_bits))) <> 0L then
    Invalid "physical address uses reserved high bits"
  else if level = 4 && bit raw 7 then Invalid "page size bit in pml4 entry"
  else if level = 3 && bit raw 7 && not features.gb_pages then Invalid "1 gib pages are not exposed to the guest"
  else
    let address = Int64.logand raw (Int64.logand (mask features.phys_bits) (Int64.lognot 0xfffL)) in
    if level = 1 then Leaf (12, Physical.of_int64 address)
    else if bit raw 7 then
      let bits = shift level in
      (* huge leaf: [ frame | reserved | pat | flags ], bit 12 stays out of the frame *)
      if Int64.logand raw (Int64.logand (mask bits) (Int64.lognot 0x1fffL)) <> 0L then
        Invalid "misaligned huge page uses reserved address bits"
      else Leaf (bits, Physical.of_int64 (align address bits))
    else Table (Physical.of_int64 address)

let error_code context request ~present ~reserved =
  (if present then 1 else 0)
  lor (if request.access = Write then 2 else 0)
  lor (if request.privilege = User then 4 else 0)
  lor (if reserved then 8 else 0)
  lor (if request.access = Execute &&
    (Address.bit context.registers.efer 11 || Address.bit context.registers.cr4 20) then 16 else 0)

let walk context read address =
  validate context;
  let virtual_raw = Address.Virtual.to_int64 address in
  if not (Address.canonical virtual_raw) then
    { trace = []; outcome = Fault { vector = 13; error_code = 0; reason = "noncanonical linear address"; level = None } }
  else
    let rec go level table permissions trace =
      match read table with
      | Error reason -> { trace = List.rev trace; outcome = Incomplete reason }
      | Ok page when String.length page <> 4096 ->
          { trace = List.rev trace; outcome = Incomplete "table read is not 4096 bytes" }
      | Ok page ->
          let index = Int64.(to_int (logand (shift_right_logical virtual_raw (shift level)) 511L)) in
          let raw = String.get_int64_le page (index * 8) in
          let effective = narrow permissions raw in
          let step = { level; table; index; raw; effective } in
          let trace = step :: trace in
          match decode context.features ~nxe:(Address.bit context.registers.efer 11) ~level raw with
          | Absent -> { trace = List.rev trace; outcome = Fault {
              vector = 14; error_code = 0; reason = "entry not present"; level = Some level } }
          | Invalid reason -> { trace = List.rev trace; outcome = Fault {
              vector = 14; error_code = 9; reason; level = Some level } }
          | Table next -> go (level - 1) next effective trace
          | Leaf (bits, base) ->
              let trace = List.rev trace in
              let physical_address = Address.Physical.of_int64
                Int64.(add (Address.Physical.to_int64 base) (logand virtual_raw (Address.mask bits))) in
              { trace; outcome = Mapped { virtual_address = address; physical_address;
                size = Int64.shift_left 1L bits; permissions = effective; leaf = raw; trace } }
    in
    go 4 (root context) unrestricted []

let explain context read address request =
  let result = walk context read address in
  let fault reason level =
    { result with outcome = Fault { vector = 14;
      error_code = error_code context request ~present:true ~reserved:false;
      reason; level } }
  in
  match result.outcome with
  | Incomplete _ -> result
  | Fault f when f.vector = 13 -> result
  | Fault f -> { result with outcome = Fault { f with error_code =
      error_code context request ~present:(f.error_code land 1 <> 0)
        ~reserved:(f.error_code land 8 <> 0) } }
  | Mapped mapping ->
      let p = mapping.permissions and r = context.registers in
      let first predicate =
        List.find_opt predicate result.trace |> Option.map (fun (step : step) -> step.level)
      in
      if request.privilege = User && not p.user then
        fault "supervisor mapping denies user access" (first (fun s -> not (Address.bit s.raw 2)))
      else if request.access = Write && not p.writable &&
        (request.privilege = User || Address.bit r.cr0 16) then
        fault "read-only entry denies write" (first (fun s -> not (Address.bit s.raw 1)))
      else if request.access = Execute && not p.executable then
        fault "nx entry denies instruction fetch" (first (fun s -> Address.bit s.raw 63))
      else if request.privilege = Supervisor && p.user && request.access = Execute && Address.bit r.cr4 20 then
        fault "smep denies supervisor fetch from user mapping" None
      else if request.privilege = Supervisor && p.user && request.access <> Execute &&
        Address.bit r.cr4 21 && not request.ac then
        fault "smap denies explicit supervisor data access with ac clear" None
      else result

type state = Present of mapping | Unknown of string | Broken of string
type region = { start : int64; length : int64; state : state }

let last region = Int64.pred (Int64.add region.start region.length)

let enumerate ?(max_entries = 2_000_000) context read =
  validate context;
  let count = ref 0 and acc = ref [] in
  let emit start length state = acc := { start; length; state } :: !acc in
  let canonicalise x =
    if Address.bit x 47 then Int64.logor x 0xffff000000000000L else x
  in
  let rec go level table prefix permissions trace =
    match read table with
    | Error reason ->
        if level = 4 then begin
          emit 0L 0x800000000000L (Unknown reason);
          emit 0xffff800000000000L 0x800000000000L (Unknown reason)
        end else emit (canonicalise prefix) (Int64.mul 512L (span level)) (Unknown reason)
    | Ok page ->
        if String.length page <> 4096 then invalid_arg "table read is not 4096 bytes";
        for index = 0 to 511 do
          incr count;
          if !count > max_entries then raise (Limit "page-table traversal budget exceeded");
          let raw = String.get_int64_le page (index * 8) in
          let prefix = Int64.logor prefix (Int64.shift_left (Int64.of_int index) (shift level)) in
          let start = canonicalise prefix in
          let effective = narrow permissions raw in
          let trace = { level; table; index; raw; effective } :: trace in
          match decode context.features ~nxe:(Address.bit context.registers.efer 11) ~level raw with
          | Absent -> ()
          | Invalid reason -> emit start (span level) (Broken reason)
          | Table next -> go (level - 1) next prefix effective trace
          | Leaf (bits, physical_address) ->
              let trace = List.rev trace in
              let mapping = { virtual_address = Address.Virtual.of_int64 start; physical_address;
                size = Int64.shift_left 1L bits; permissions = effective; leaf = raw; trace } in
              emit start mapping.size (Present mapping)
        done
  in
  go 4 (root context) 0L unrestricted [];
  List.rev !acc
