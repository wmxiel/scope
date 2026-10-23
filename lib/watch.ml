open Model

type event = {
  sample : int;
  time : float;
  kind : string;
  before : Capture.t option;
  after : Capture.t;
  changes : Analysis.change list;
  context_changes : string list;
  aliases : Analysis.alias list;
  complete : bool;
  directory : string;
  mappings : int;
  bytes : int64;
  executable : int;
  writable : int;
  huge : int;
}

let run ~capture ~wait ~emit ~directory ~interval ~count ~retain ~max_entries ~max_pairs
    ~include_ad ~scan_aliases ~selected () =
  if count < 0 || retain < 1 || not (Float.is_finite interval) || interval <= 0. then
    invalid_arg "invalid watch sampling or retention settings";
  if Sys.file_exists directory then invalid_arg "watch output directory must not already exist";
  Unix.mkdir directory 0o700;
  let retained = Queue.create () in
  let previous = ref None and identity = ref None in
  let findings = ref false and incomplete = ref false in
  let statistics = ref (0, 0L, 0, 0, 0) in
  let notify sample kind before after changes context_changes aliases complete path =
    let mappings, bytes, executable, writable, huge = !statistics in
    emit { sample; time = Unix.gettimeofday (); kind; before; after; changes; context_changes;
      aliases; complete; directory = path; mappings; bytes; executable; writable; huge }
  in
  let publish sample kind before after changes context_changes aliases complete =
    let path = Filename.concat directory (Printf.sprintf "%08d" sample) in
    Unix.mkdir path 0o700;
    Option.iter (Capture.save (Filename.concat path "before")) before;
    Capture.save (Filename.concat path "after") after;
    Queue.add path retained;
    while Queue.length retained > retain do
      let oldest = Queue.take retained in
      List.iter (fun name -> let file = Filename.concat oldest name in
        if Sys.file_exists file then Unix.unlink file) ["before"; "after"];
      Unix.rmdir oldest
    done;
    notify sample kind before after changes context_changes aliases complete path
  in
  let rec loop sample =
    let after = capture () in
    let context = Capture.context after in
    (match !identity with
    | None -> identity := Some context.identity
    | Some expected when expected <> context.identity -> failwith "domain identity changed between watch samples"
    | _ -> ());
    let regions = Paging.enumerate ~max_entries context (Capture.read after) |> List.filter selected in
    statistics := List.fold_left (fun (n, bytes, x, w, huge) region -> match region.Paging.state with
      | Paging.Present m -> n + 1, Int64.add bytes m.size,
          x + (if m.permissions.executable then 1 else 0), w + (if m.permissions.writable then 1 else 0),
          huge + (if m.size > 4096L then 1 else 0)
      | _ -> n, bytes, x, w, huge) (0, 0L, 0, 0, 0) regions;
    let complete = List.for_all (fun r -> match r.Paging.state with Paging.Unknown _ -> false | _ -> true) regions in
    let aliases = if scan_aliases then Analysis.aliases ~max_pairs regions else [] in
    if aliases <> [] || List.exists (fun r -> match r.Paging.state with Paging.Broken _ -> true | _ -> false) regions then
      findings := true;
    if not complete then begin
      incomplete := true;
      publish sample "incomplete" !previous after [] [] aliases false
    end else begin
      (match !previous with
      | None -> publish sample "baseline" None after [] [] aliases true
      | Some before ->
          let earlier = Capture.context before in
          let context_changes = Model.context_changes earlier context in
          if Model.root earlier <> Model.root context then
            publish sample "address_space" (Some before) after [] context_changes aliases true
          else begin
            let before_regions = Paging.enumerate ~max_entries earlier (Capture.read before) in
            let changes = Analysis.diff ~include_ad before_regions regions |> List.filter (fun (c : Analysis.change) ->
              selected { Paging.start = c.start; length = c.length; state = Paging.Unknown "" }) in
            if changes <> [] || context_changes <> [] then begin
              findings := true;
              publish sample "change" (Some before) after changes context_changes aliases true
            end else notify sample "sample" (Some before) after [] [] aliases true ""
          end);
      previous := Some after
    end;
    if count = 0 || sample < count then begin wait interval; loop (sample + 1) end
  in
  (try loop 1 with exn ->
    if Array.length (Sys.readdir directory) = 0 then Unix.rmdir directory;
    raise exn);
  if !incomplete then 2 else if !findings then 1 else 0
