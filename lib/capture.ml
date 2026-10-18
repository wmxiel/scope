module Frames = Map.Make (struct
  type t = int64
  let compare = Address.compare
end)

type t = {
  context : Model.context;
  frames : (string, string) result Frames.t;
}

let maximum_pages = 65536
let maximum_bytes = 280_000_000
let context capture = capture.context
let pages capture = Frames.cardinal capture.frames

let make context frames =
  Model.validate context;
  if List.length frames > maximum_pages then invalid_arg "too many capture pages";
  let frames = List.fold_left (fun map (address, page) ->
    let raw = Address.Physical.to_int64 address in
    if Int64.logand raw 0xfffL <> 0L || Address.compare raw (Address.mask context.features.phys_bits) > 0 then
      invalid_arg "unaligned or out-of-range table frame";
    if Frames.mem raw map then invalid_arg "duplicate table frame";
    (match page with
    | Ok bytes when String.length bytes <> 4096 -> invalid_arg "table must contain 4096 bytes"
    | Error reason when String.length reason > 4096 -> invalid_arg "table error is too long"
    | _ -> ());
    Frames.add raw page map) Frames.empty frames
  in
  { context; frames }

let read capture address =
  let raw = Address.Physical.to_int64 address in
  match Frames.find_opt raw capture.frames with
  | Some page -> page
  | None -> Error ("table not captured at " ^ Address.hex raw)

let with_root capture root =
  let context = { capture.context with root_override = Some root } in
  Model.validate context;
  { capture with context }

let collect ?(max_pages = maximum_pages) context reader =
  Model.validate context;
  if max_pages < 1 || max_pages > maximum_pages then invalid_arg "invalid capture page budget";
  let frames = ref Frames.empty and visited = Hashtbl.create 64 in
  let rec go level address =
    let raw = Address.Physical.to_int64 address in
    if not (Hashtbl.mem visited (level, raw)) then begin
      Hashtbl.add visited (level, raw) ();
      let page = match Frames.find_opt raw !frames with
        | Some page -> page
        | None ->
            if Frames.cardinal !frames >= max_pages then raise (Model.Limit "capture page budget exceeded");
            let page = reader address in
            (match page with Ok bytes when String.length bytes <> 4096 -> invalid_arg "short table read" | _ -> ());
            frames := Frames.add raw page !frames;
            page
      in
      match page with
      | Error _ -> ()
      | Ok bytes ->
          for index = 0 to 511 do
            let entry = String.get_int64_le bytes (index * 8) in
            match Paging.decode context.features ~nxe:(Address.bit context.registers.efer 11) ~level entry with
            | Paging.Table next -> go (level - 1) next
            | _ -> ()
          done
    end
  in
  go 4 (Model.root context);
  { context; frames = !frames }

let complete capture =
  let closure = collect capture.context (read capture) in
  Frames.for_all (fun _ -> function Ok _ -> true | Error _ -> false) closure.frames

let add_u32 buffer n =
  let bytes = Bytes.create 4 in
  Bytes.set_int32_le bytes 0 (Int32.of_int n);
  Buffer.add_bytes buffer bytes

let add_u64 buffer n =
  let bytes = Bytes.create 8 in
  Bytes.set_int64_le bytes 0 n;
  Buffer.add_bytes buffer bytes

let add_string buffer s =
  if String.length s > 4096 then invalid_arg "capture string exceeds 4096 bytes";
  add_u32 buffer (String.length s);
  Buffer.add_string buffer s

let encode capture =
  let buffer = Buffer.create (128 + pages capture * 4112) in
  Buffer.add_string buffer "SCOPE\000\001\n";
  let c = capture.context in
  add_u32 buffer c.domid;
  add_u32 buffer c.vcpu;
  add_u32 buffer c.features.phys_bits;
  add_u32 buffer ((if c.features.nx then 1 else 0) lor (if c.features.gb_pages then 2 else 0));
  let r = c.registers in
  List.iter (add_u64 buffer) [r.cr0; r.cr2; r.cr3; r.cr4; r.efer; r.rflags; r.rip];
  add_u32 buffer (if c.root_override = None then 0 else 1);
  add_u64 buffer (Option.value c.root_override ~default:0L);
  List.iter (add_string buffer) [c.source; c.consistency; c.identity];
  add_u32 buffer (pages capture);
  Frames.iter (fun address page ->
    add_u64 buffer address;
    match page with
    | Ok bytes -> add_u32 buffer 0; Buffer.add_string buffer bytes
    | Error reason -> add_u32 buffer 1; add_string buffer reason) capture.frames;
  let payload = Buffer.contents buffer in
  payload ^ Digest.string payload

let save path capture =
  let bytes = encode capture in
  let temporary, channel = Filename.open_temp_file ~temp_dir:(Filename.dirname path) ".scope" ".tmp" in
  Fun.protect ~finally:(fun () -> close_out_noerr channel; if Sys.file_exists temporary then Sys.remove temporary)
    (fun () ->
      output_string channel bytes;
      flush channel;
      Unix.fsync (Unix.descr_of_out_channel channel);
      close_out channel;
      Unix.rename temporary path)

let load path =
  let channel = open_in_bin path in
  let bytes = Fun.protect ~finally:(fun () -> close_in_noerr channel) (fun () ->
    let length = in_channel_length channel in
    if length > maximum_bytes || length < 24 then invalid_arg "capture size outside format bounds";
    really_input_string channel length)
  in
  let limit = String.length bytes - 16 in
  if Digest.string (String.sub bytes 0 limit) <> String.sub bytes limit 16 then
    invalid_arg "capture checksum mismatch";
  let position = ref 0 in
  let take n =
    if n < 0 || n > limit - !position then invalid_arg "truncated capture";
    let s = String.sub bytes !position n in
    position := !position + n;
    s
  in
  let u32 () =
    let n = Int64.logand (Int64.of_int32 (String.get_int32_le (take 4) 0)) 0xffffffffL in
    if n > Int64.of_int max_int then invalid_arg "capture integer overflow";
    Int64.to_int n
  in
  let u64 () = String.get_int64_le (take 8) 0 in
  let string () = let n = u32 () in if n > 4096 then invalid_arg "capture string too long"; take n in
  if take 8 <> "SCOPE\000\001\n" then invalid_arg "unsupported capture format";
  let domid = u32 () in
  let vcpu = u32 () in
  let phys_bits = u32 () in
  let flags = u32 () in
  if flags land (lnot 3) <> 0 then invalid_arg "unsupported feature flags";
  let cr0 = u64 () in
  let cr2 = u64 () in
  let cr3 = u64 () in
  let cr4 = u64 () in
  let efer = u64 () in
  let rflags = u64 () in
  let rip = u64 () in
  let root_tag = u32 () in
  let root_value = u64 () in
  let root_override = match root_tag, root_value with
    | 0, 0L -> None | 1, value -> Some value | _ -> invalid_arg "invalid root override record"
  in
  let source = string () in
  let consistency = string () in
  let identity = string () in
  let count = u32 () in
  if count > maximum_pages then invalid_arg "too many capture pages";
  let frames = List.init count (fun _ ->
    let address = Address.Physical.of_int64 (u64 ()) in
    let page = match u32 () with
      | 0 -> Ok (take 4096)
      | 1 -> Error (string ())
      | _ -> invalid_arg "invalid table record tag"
    in
    address, page)
  in
  if !position <> limit then invalid_arg "trailing capture data";
  make { registers = { cr0; cr2; cr3; cr4; efer; rflags; rip }; root_override;
    features = { phys_bits; nx = flags land 1 <> 0; gb_pages = flags land 2 <> 0 };
    source; consistency; identity; domid; vcpu } frames

let import ~source path =
  let channel = open_in path in
  Fun.protect ~finally:(fun () -> close_in_noerr channel) (fun () ->
    if in_channel_length channel > maximum_bytes * 3 then invalid_arg "import exceeds format size budget";
    let context = ref None and frames = ref [] and count = ref 0 in
    let number = ref 0 in
    (try while true do
      let line = input_line channel in
      incr number;
      if String.length line > 16384 then invalid_arg "import line exceeds 16384 bytes";
      let fields = String.split_on_char ' ' line |> List.filter ((<>) "") in
      match fields with
      | [] -> ()
      | ["context"; cr0; cr2; cr3; cr4; efer; rflags; rip; phys_bits; nx; gb_pages] ->
          if !context <> None then invalid_arg "duplicate import context";
          let boolean = function "0" -> false | "1" -> true | _ -> invalid_arg "invalid feature boolean" in
          let open Model in
          context := Some { registers = { cr0 = Address.parse cr0; cr2 = Address.parse cr2;
              cr3 = Address.parse cr3; cr4 = Address.parse cr4; efer = Address.parse efer;
              rflags = Address.parse rflags; rip = Address.parse rip };
            features = { phys_bits = int_of_string phys_bits; nx = boolean nx; gb_pages = boolean gb_pages };
            root_override = None; source; consistency = "offline import; producer defines consistency";
            identity = "import"; domid = 0; vcpu = 0 }
      | ["page"; address; hex] ->
          incr count;
          if !count > maximum_pages then invalid_arg "too many imported pages";
          if String.length hex <> 8192 then invalid_arg "page hex must contain 8192 digits";
          let digit = function
            | '0' .. '9' as c -> Char.code c - Char.code '0'
            | 'a' .. 'f' as c -> Char.code c - Char.code 'a' + 10
            | 'A' .. 'F' as c -> Char.code c - Char.code 'A' + 10
            | _ -> invalid_arg "invalid page hex"
          in
          let bytes = String.init 4096 (fun i -> Char.chr ((digit hex.[2*i] lsl 4) lor digit hex.[2*i+1])) in
          frames := (Address.Physical.of_int64 (Address.parse address), Ok bytes) :: !frames
      | "missing" :: address :: reason ->
          incr count;
          if !count > maximum_pages then invalid_arg "too many imported pages";
          frames := (Address.Physical.of_int64 (Address.parse address), Error (String.concat " " reason)) :: !frames
      | _ -> invalid_arg (Printf.sprintf "invalid import record on line %d" !number)
    done with End_of_file -> ());
    match !context with None -> invalid_arg "missing import context" | Some context -> make context !frames)
