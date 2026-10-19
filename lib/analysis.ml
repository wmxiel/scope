open Model
open Paging

type change = { start : int64; length : int64; before : state option; after : state option; kinds : string list }

let offset_mapping (region : region) address mapping =
  let offset = Int64.sub address region.start in
  { mapping with virtual_address = Address.Virtual.of_int64 address;
    physical_address = Address.Physical.of_int64 (Int64.add (Address.Physical.to_int64 mapping.physical_address) offset) }

let state_at (region : region) address = match region.state with
  | Present mapping -> Present (offset_mapping region address mapping)
  | state -> state

let attributes mapping =
  let huge = mapping.size <> 4096L in
  let pat = Address.bit mapping.leaf (if huge then 12 else 7) in
  Int64.logor (Int64.logand mapping.leaf 0x118L) (if pat then 0x80L else 0L)

let history (mapping : mapping) =
  let leaf = List.length mapping.trace - 1 in
  List.mapi (fun index (s : step) -> Int64.logand s.raw (if index = leaf then 0x60L else 0x20L)) mapping.trace

let differences ~include_ad before after =
  match before, after with
  | Some (Unknown _), _ | _, Some (Unknown _) -> ["incomplete"]
  | Some (Broken a), Some (Broken b) when a = b -> []
  | Some (Broken _), _ | _, Some (Broken _) -> ["invalid"]
  | None, None -> []
  | None, Some _ -> ["added"]
  | Some _, None -> ["removed"]
  | Some (Present a), Some (Present b) ->
      List.filter_map (fun (changed, kind) -> if changed then Some kind else None) [
        (a.physical_address <> b.physical_address, "backing");
        (a.permissions <> b.permissions, "permissions");
        (a.size <> b.size, "page_size");
        (attributes a <> attributes b, "attributes");
        (include_ad && history a <> history b, "accessed_dirty") ]

let diff ?(include_ad = false) before after =
  let boundaries regions = List.fold_left (fun acc (region : region) ->
    let finish = Int64.add region.start region.length in
    region.start :: if finish = 0L then acc else finish :: acc) [] regions
  in
  let points = List.sort_uniq Address.compare (boundaries before @ boundaries after) in
  let before = ref before and after = ref after in
  let lookup regions address =
    let rec advance () = match !regions with
      | region :: rest when Address.compare (last region) address < 0 -> regions := rest; advance ()
      | _ -> ()
    in
    advance ();
    match !regions with
    | region :: _ when Address.compare region.start address <= 0 -> Some (state_at region address)
    | _ -> None
  in
  let rec go acc = function
    | [] -> List.rev acc
    | start :: rest ->
        let finish = match rest with next :: _ -> Int64.pred next | [] -> -1L in
        let a = lookup before start and b = lookup after start in
        let kinds = differences ~include_ad a b in
        let acc = if kinds = [] then acc else {
          start; length = Int64.succ (Int64.sub finish start); before = a; after = b; kinds } :: acc in
        go acc rest
  in
  go [] points

type alias = { physical : int64; length : int64; writable : mapping; executable : mapping }

let aliases ?(max_pairs = 100_000) regions =
  let module Active = Map.Make (Int) in
  let mappings = List.filter_map (fun r -> match r.state with Present m -> Some m | _ -> None) regions in
  let physical m = Address.Physical.to_int64 m.physical_address in
  let finish m = Int64.add (physical m) m.size in
  let events = List.mapi (fun id mapping ->
    [physical mapping, 1, id, mapping; finish mapping, 0, id, mapping]) mappings |> List.concat
    |> List.sort (fun (a, ak, ai, _) (b, bk, bi, _) ->
      let compared = Address.compare a b in
      if compared <> 0 then compared else let compared = Int.compare ak bk in
      if compared <> 0 then compared else Int.compare ai bi)
  in
  let writable = ref Active.empty and executable = ref Active.empty in
  let acc = ref [] and count = ref 0 in
  let emit writable executable =
    incr count;
    if !count > max_pairs then raise (Limit "alias pair budget exceeded");
    let start = if physical writable > physical executable then physical writable else physical executable in
    let stop = min (finish writable) (finish executable) in
    acc := { physical = start; length = Int64.sub stop start; writable; executable } :: !acc
  in
  List.iter (fun (_, kind, id, mapping) ->
    if kind = 0 then begin
      writable := Active.remove id !writable;
      executable := Active.remove id !executable
    end else begin
      (* end -> start at equal addresses keeps adjacent frames out of the overlap set *)
      if mapping.permissions.writable then
        Active.iter (fun _ other -> emit mapping other) !executable;
      if mapping.permissions.executable then
        Active.iter (fun _ other -> emit other mapping) !writable;
      if mapping.permissions.writable then writable := Active.add id mapping !writable;
      if mapping.permissions.executable then executable := Active.add id mapping !executable
    end) events;
  List.rev !acc
