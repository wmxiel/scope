open Scope
open Model

exception Usage of string
exception Interrupted of int

let usage = "scope 0.1.0\n\n\
  scope info CAPTURE\n\
  scope walk CAPTURE ADDRESS\n\
  scope explain CAPTURE ADDRESS --access read|write|execute --privilege supervisor|user\n\
  scope mappings CAPTURE\n\
  scope aliases CAPTURE\n\
  scope diff BEFORE AFTER [--include-ad]\n\
  scope capture DOMAIN OUTPUT --vcpu N --phys-bits N --nx on|off --gb-pages on|off [--pause]\n\
  scope watch DOMAIN DIRECTORY --vcpu N --phys-bits N --nx on|off --gb-pages on|off [--pause]\n\
  scope import TRANSCRIPT OUTPUT\n\
  scope demo DIRECTORY\n\n\
addresses are unsigned decimal or 0x-prefixed hexadecimal\n\
exit status: 0 success, 1 fault or findings, 2 incomplete or operational failure, 64 usage\n"

type options = {
  mutable json : bool;
  mutable root : int64 option;
  mutable max_entries : int;
  mutable max_pages : int;
  mutable max_pairs : int;
  mutable include_ad : bool;
  mutable access : access option;
  mutable privilege : privilege option;
  mutable ac : bool option;
  mutable vcpu : int option;
  mutable phys_bits : int option;
  mutable nx : bool option;
  mutable gb_pages : bool option;
  mutable pause : bool;
  mutable first : int64 option;
  mutable last : int64 option;
  mutable source : string;
  mutable interval : float;
  mutable count : int;
  mutable retain : int;
  mutable scan_aliases : bool;
}

let boolean = function "on" -> true | "off" -> false | _ -> raise (Usage "expected on or off")
let required name = function Some value -> value | None -> raise (Usage ("missing " ^ name))

let parse () =
  let options = { json = false; root = None; max_entries = 2_000_000; max_pages = 65536;
    max_pairs = 100_000; include_ad = false; access = None; privilege = None; ac = None;
    vcpu = None; phys_bits = None; nx = None; gb_pages = None; pause = false;
    first = None; last = None; source = "offline import";
    interval = 2.; count = 0; retain = 32; scan_aliases = false } in
  let positional = ref [] in
  let seen = Hashtbl.create 16 in
  let wrap flag action = fun value ->
    if Hashtbl.mem seen flag then raise (Usage ("duplicate option " ^ flag));
    Hashtbl.add seen flag ();
    action value
  in
  let specs = [
    "--interval", Arg.Float (wrap "--interval" (fun n -> options.interval <- n)), "SECONDS delay after each watch sample";
    "--count", Arg.Int (wrap "--count" (fun n -> options.count <- n)), "N watch samples, zero means until interrupted";
    "--retain", Arg.Int (wrap "--retain" (fun n -> options.retain <- n)), "N evidence pairs to retain";
    "--aliases", Arg.Unit (wrap "--aliases" (fun () -> options.scan_aliases <- true)), " scan writable/executable aliases while watching";
    "--json", Arg.Unit (wrap "--json" (fun () -> options.json <- true)), " emit scope.report.v1 json";
    "--root", Arg.String (wrap "--root" (fun s -> options.root <- Some (Address.parse s))), "ADDRESS select root while preserving captured cr3";
    "--max-entries", Arg.Int (wrap "--max-entries" (fun n -> options.max_entries <- n)), "N traversal budget";
    "--max-pages", Arg.Int (wrap "--max-pages" (fun n -> options.max_pages <- n)), "N capture page budget";
    "--max-pairs", Arg.Int (wrap "--max-pairs" (fun n -> options.max_pairs <- n)), "N alias output budget";
    "--include-ad", Arg.Unit (wrap "--include-ad" (fun () -> options.include_ad <- true)), " include accessed and dirty changes";
    "--access", Arg.Symbol (["read"; "write"; "execute"], wrap "--access" (fun s ->
      options.access <- Some (match s with "read" -> Read | "write" -> Write | _ -> Execute))), " requested access";
    "--privilege", Arg.Symbol (["supervisor"; "user"], wrap "--privilege" (fun s ->
      options.privilege <- Some (if s = "user" then User else Supervisor))), " access privilege";
    "--ac", Arg.String (wrap "--ac" (fun s -> options.ac <- Some (boolean s))), "on|off override captured ac for explicit data accesses";
    "--vcpu", Arg.Int (wrap "--vcpu" (fun n -> options.vcpu <- Some n)), "N vcpu to capture";
    "--phys-bits", Arg.Int (wrap "--phys-bits" (fun n -> options.phys_bits <- Some n)), "N guest maxphyaddr";
    "--nx", Arg.String (wrap "--nx" (fun s -> options.nx <- Some (boolean s))), "on|off guest nx capability";
    "--gb-pages", Arg.String (wrap "--gb-pages" (fun s -> options.gb_pages <- Some (boolean s))), "on|off guest 1 gib page capability";
    "--pause", Arg.Unit (wrap "--pause" (fun () -> options.pause <- true)), " hold a controller pause during capture";
    "--start", Arg.String (wrap "--start" (fun s -> options.first <- Some (Address.parse s))), "ADDRESS select overlapping regions";
    "--end", Arg.String (wrap "--end" (fun s -> options.last <- Some (Address.parse s))), "ADDRESS inclusive range end";
    "--source", Arg.String (wrap "--source" (fun s -> options.source <- s)), "TEXT import provenance";
  ] in
  Arg.parse_argv Sys.argv specs (fun value -> positional := value :: !positional) usage;
  if options.max_entries < 1 || options.max_pages < 1 || options.max_pairs < 1 then raise (Usage "budgets must be positive");
  if not (Float.is_finite options.interval) || options.interval <= 0. || options.count < 0 || options.retain < 1 then
    raise (Usage "watch interval and retention must be positive; count must be nonnegative");
  (match options.first, options.last with Some a, Some b when Address.compare a b > 0 ->
    raise (Usage "range start exceeds range end") | _ -> ());
  options, List.rev !positional, seen

let selected options (region : Paging.region) =
  (match options.first with None -> true | Some first -> Address.compare (Paging.last region) first >= 0) &&
  (match options.last with None -> true | Some last -> Address.compare region.start last <= 0)

let complete regions = List.for_all (fun (region : Paging.region) ->
  match region.state with Paging.Unknown _ -> false | _ -> true) regions

let invalid regions = List.exists (fun (region : Paging.region) ->
  match region.state with Paging.Broken _ -> true | _ -> false) regions

let run options positional seen =
  let command = match positional with command :: _ -> command | [] -> raise (Usage usage) in
  let allowed = ["--json"] @ (match command with
    | "info" -> []
    | "walk" -> ["--root"]
    | "explain" -> ["--root"; "--access"; "--privilege"; "--ac"]
    | "mappings" -> ["--root"; "--max-entries"; "--start"; "--end"]
    | "aliases" -> ["--root"; "--max-entries"; "--max-pairs"; "--start"; "--end"]
    | "diff" -> ["--root"; "--max-entries"; "--start"; "--end"; "--include-ad"]
    | "capture" -> ["--root"; "--max-pages"; "--vcpu"; "--phys-bits"; "--nx"; "--gb-pages"; "--pause"]
    | "watch" -> ["--root"; "--max-pages"; "--max-entries"; "--max-pairs"; "--vcpu"; "--phys-bits";
        "--nx"; "--gb-pages"; "--pause"; "--interval"; "--count"; "--retain"; "--aliases";
        "--include-ad"; "--start"; "--end"]
    | "import" -> ["--source"]
    | "demo" -> []
    | _ -> raise (Usage ("unknown command: " ^ command))) in
  Hashtbl.iter (fun flag () -> if not (List.mem flag allowed) then raise (Usage (flag ^ " does not apply to " ^ command))) seen;
  let load path =
    let capture = Capture.load path in
    match options.root with None -> capture | Some root -> Capture.with_root capture root
  in
  let enumerate capture = Paging.enumerate ~max_entries:options.max_entries (Capture.context capture) (Capture.read capture) in
  let output_context capture = if not options.json then Report.print_context (Capture.context capture) in
  let emit capture complete fields = Json.print (Report.envelope command (Capture.context capture) complete fields) in
  match positional with
  | ["watch"; domain; directory] ->
      let domid = try int_of_string domain with Failure _ -> raise (Usage "invalid domain id") in
      let vcpu = required "--vcpu" options.vcpu in
      let features = { phys_bits = required "--phys-bits" options.phys_bits;
        nx = required "--nx" options.nx; gb_pages = required "--gb-pages" options.gb_pages } in
      let capture () = Xen.capture ~domid ~vcpu ~pause:options.pause ~features ~root:options.root ~max_pages:options.max_pages in
      let emit (event : Watch.event) =
        let context = Capture.context event.after in
        if options.json then Json.print (Report.envelope "watch" context event.complete [
          "event", Json.String event.kind; "sample", Json.Int event.sample;
          "time", Json.String (Printf.sprintf "%.6f" event.time);
          "evidence", (if event.directory = "" then Json.Null else Json.String event.directory);
          "summary", Json.Object ["mappings", Json.Int event.mappings; "mapped_virtual_bytes", Json.hex event.bytes;
            "executable", Json.Int event.executable; "writable", Json.Int event.writable; "huge", Json.Int event.huge];
          "context_changes", Json.List (List.map Json.string event.context_changes);
          "changes", Json.List (List.map Report.change event.changes);
          "aliases", Json.List (List.map Report.alias event.aliases)])
        else begin
          Printf.printf "time=%.3f sample=%d event=%s root=%s mappings=%d bytes=%s executable=%d writable=%d huge=%d complete=%b\n"
            event.time event.sample event.kind (Address.hex (Address.Physical.to_int64 (Model.root context)))
            event.mappings (Address.hex event.bytes) event.executable event.writable event.huge event.complete;
          List.iter (fun (change : Analysis.change) ->
            Printf.printf "  %s length=%s changes=%s\n" (Address.hex change.start) (Address.hex change.length)
              (String.concat "," change.kinds);
            List.iter (fun (label, state) -> match state with
              | Some (Paging.Present m) -> Printf.printf "    %s physical=%s page_size=%s %s\n"
                  label (Address.hex (Address.Physical.to_int64 m.physical_address)) (Address.hex m.size) (Report.rights m.permissions)
              | _ -> ()) ["before", change.before; "after", change.after]) event.changes;
          if event.directory <> "" then Printf.printf "  evidence=%S aliases=%d context_changes=%s\n"
            event.directory (List.length event.aliases) (String.concat "," event.context_changes);
          if event.directory <> "" then List.iter (fun (alias : Analysis.alias) ->
            Printf.printf "  alias physical=%s length=%s writable=%s executable=%s\n"
              (Address.hex alias.physical) (Address.hex alias.length)
              (Address.hex (Address.Virtual.to_int64 alias.writable.virtual_address))
              (Address.hex (Address.Virtual.to_int64 alias.executable.virtual_address))) event.aliases
        end;
        flush stdout
      in
      (try Watch.run ~capture ~wait:Unix.sleepf ~emit ~directory ~interval:options.interval
        ~count:options.count ~retain:options.retain ~max_entries:options.max_entries ~max_pairs:options.max_pairs
        ~include_ad:options.include_ad ~scan_aliases:options.scan_aliases ~selected:(selected options) ()
      with Interrupted _ -> 0)
  | ["demo"; directory] ->
      Demo.write directory;
      if options.json then Json.print (Json.Object ["schema", Json.String "scope.report.v1";
        "command", Json.String "demo"; "directory", Json.String directory])
      else Printf.printf "captures=%s/before,%s/after source=synthetic\n" directory directory;
      0
  | ["import"; transcript; destination] ->
      let capture = Capture.import ~source:options.source transcript in
      let complete = Capture.complete capture in
      Capture.save destination capture;
      if options.json then emit capture complete ["path", Json.String destination; "pages", Json.Int (Capture.pages capture)]
      else Printf.printf "capture=%s pages=%d complete=%b\n" destination (Capture.pages capture) complete;
      if complete then 0 else 2
  | ["capture"; domain; destination] ->
      let domid = try int_of_string domain with Failure _ -> raise (Usage "invalid domain id") in
      let vcpu = required "--vcpu" options.vcpu in
      let features = { phys_bits = required "--phys-bits" options.phys_bits;
        nx = required "--nx" options.nx; gb_pages = required "--gb-pages" options.gb_pages } in
      let capture = Xen.capture ~domid ~vcpu ~pause:options.pause ~features ~root:options.root ~max_pages:options.max_pages in
      let complete = Capture.complete capture in
      Capture.save destination capture;
      output_context capture;
      if options.json then emit capture complete ["path", Json.String destination; "pages", Json.Int (Capture.pages capture)]
      else Printf.printf "capture=%s pages=%d complete=%b\n" destination (Capture.pages capture) complete;
      if complete then 0 else 2
  | ["info"; path] ->
      let capture = load path in
      let complete = Capture.complete capture in
      output_context capture;
      if options.json then emit capture complete ["pages", Json.Int (Capture.pages capture); "xen_available", Json.Bool (Xen.available ())]
      else Printf.printf "pages=%d complete=%b xen_available=%b\n" (Capture.pages capture) complete (Xen.available ());
      if complete then 0 else 2
  | [("walk" | "explain"); path; address] ->
      let capture = load path in
      let context = Capture.context capture in
      let address = Address.Virtual.of_int64 (Address.parse address) in
      let request = if command = "walk" then None else Some {
        access = required "--access" options.access;
        privilege = required "--privilege" options.privilege;
        ac = Option.value options.ac ~default:(Address.bit context.registers.rflags 18) } in
      let result = match request with
        | None -> Paging.walk context (Capture.read capture) address
        | Some request -> Paging.explain context (Capture.read capture) address request
      in
      let complete = match result.outcome with Incomplete _ -> false | _ -> true in
      output_context capture;
      if options.json then emit capture complete [
        "address", Json.hex (Address.Virtual.to_int64 address);
        "error_code_scope", Json.String (if request = None then "structural_bits_only" else "request");
        "request", Json.option (fun (request : request) -> Json.Object ["access", Json.String (access_name request.access);
          "privilege", Json.String (privilege_name request.privilege); "ac", Json.Bool request.ac]) request;
        "trace", Json.List (List.map Report.step result.trace); "result", Report.outcome result.outcome]
      else begin
        if request = None then print_endline "access=unspecified error_code=structural-bits-only";
        Option.iter (fun (request : request) -> Printf.printf "access=%s privilege=%s ac=%b\n"
          (access_name request.access) (privilege_name request.privilege) request.ac) request;
        Report.print_result result
      end;
      (match result.outcome with Mapped _ -> 0 | Fault _ -> 1 | Incomplete _ -> 2)
  | ["mappings"; path] ->
      let capture = load path in
      let regions = enumerate capture |> List.filter (selected options) in
      let complete = complete regions in
      output_context capture;
      if options.json then emit capture complete ["regions", Json.List (List.map Report.region regions)]
      else List.iter Report.print_region regions;
      if not complete then 2 else if invalid regions then 1 else 0
  | ["aliases"; path] ->
      let capture = load path in
      let regions = enumerate capture |> List.filter (selected options) in
      let complete = complete regions in
      let aliases = Analysis.aliases ~max_pairs:options.max_pairs regions in
      output_context capture;
      if options.json then emit capture complete ["aliases", Json.List (List.map Report.alias aliases);
        "regions", Json.List (List.filter_map (fun region ->
          match region.Paging.state with Paging.Present _ -> None | _ -> Some (Report.region region)) regions)]
      else begin
        List.iter (fun (alias : Analysis.alias) ->
          Printf.printf "physical=%s length=%s writable=%s executable=%s\n"
            (Address.hex alias.physical) (Address.hex alias.length)
            (Address.hex (Address.Virtual.to_int64 alias.writable.virtual_address))
            (Address.hex (Address.Virtual.to_int64 alias.executable.virtual_address));
          List.iter Report.print_step alias.writable.trace;
          List.iter Report.print_step alias.executable.trace) aliases;
        List.iter (fun region -> match region.Paging.state with Paging.Present _ -> () | _ -> Report.print_region region) regions
      end;
      if not complete then 2 else if aliases = [] && not (invalid regions) then 0 else 1
  | ["diff"; before; after] ->
      let a = load before and b = load after in
      let context_changes = Model.context_changes (Capture.context a) (Capture.context b) in
      let ra = enumerate a and rb = enumerate b in
      let changes = Analysis.diff ~include_ad:options.include_ad ra rb |> List.filter (fun (c : Analysis.change) ->
        selected options { Paging.start = c.start; length = c.length; state = Paging.Unknown "" }) in
      let complete = not (List.exists (fun (c : Analysis.change) -> List.mem "incomplete" c.kinds) changes) in
      if options.json then emit a complete ["after_context", Report.context (Capture.context b);
        "context_changes", Json.List (List.map Json.string context_changes);
        "include_ad", Json.Bool options.include_ad; "changes", Json.List (List.map Report.change changes)]
      else begin
        Report.print_context (Capture.context a);
        print_endline "after:";
        Report.print_context (Capture.context b);
        Printf.printf "context_changes=%s include_ad=%b\n" (String.concat "," context_changes) options.include_ad;
        List.iter (fun (c : Analysis.change) ->
          Printf.printf "%s length=%s changes=%s\n" (Address.hex c.start) (Address.hex c.length) (String.concat "," c.kinds);
          let print label = function
            | None -> Printf.printf "  %s absent\n" label
            | Some (Paging.Present m) -> Printf.printf "  %s physical=%s page_size=%s %s leaf=%s\n" label
                (Address.hex (Address.Physical.to_int64 m.physical_address)) (Address.hex m.size)
                (Report.rights m.permissions) (Address.hex m.leaf)
            | Some (Paging.Unknown reason) -> Printf.printf "  %s incomplete=%s\n" label reason
            | Some (Paging.Broken reason) -> Printf.printf "  %s invalid=%s\n" label reason
          in
          print "before" c.before;
          print "after" c.after) changes
      end;
      if not complete then 2 else if changes = [] && context_changes = [] then 0 else 1
  | _ -> raise (Usage ("wrong arguments for " ^ command ^ "\n" ^ usage))

let () =
  Sys.set_signal Sys.sigint (Sys.Signal_handle (fun signal -> raise (Interrupted signal)));
  Sys.set_signal Sys.sigterm (Sys.Signal_handle (fun signal -> raise (Interrupted signal)));
  let json = Array.exists ((=) "--json") Sys.argv in
  let fail code reason =
    if json then Json.output stderr (Json.Object ["schema", Json.String "scope.report.v1";
      "error", Json.String reason; "complete", Json.Bool false])
    else Printf.eprintf "scope: %s\n" reason;
    if json then output_char stderr '\n';
    exit code
  in
  try
    let options, positional, seen = parse () in
    exit (run options positional seen)
  with
  | Usage reason | Arg.Bad reason -> fail 64 reason
  | Arg.Help text -> print_string text; exit 0
  | Invalid_argument reason | Failure reason | Sys_error reason | Model.Limit reason -> fail 2 reason
  | Fun.Finally_raised exn -> fail 2 ("cleanup failed: " ^ Printexc.to_string exn)
  | Unix.Unix_error (error, operation, path) -> fail 2 (operation ^ " " ^ path ^ ": " ^ Unix.error_message error)
  | Interrupted signal -> fail 2 (Printf.sprintf "interrupted by signal %d" signal)
