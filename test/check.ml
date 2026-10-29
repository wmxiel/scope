open Scope
open Model

let count = ref 0
let check condition message = incr count; if not condition then failwith message
let virtual_address = Address.Virtual.of_int64
let physical_address = Address.Physical.of_int64
let supervisor access = { access; privilege = Supervisor; ac = false }
let user access = { access; privilege = User; ac = false }

let capture ?(context = Demo.context) pages =
  Capture.make context (List.map (fun (address, page) -> physical_address address, Ok page) pages)

let tables ?(upper = 7L) ?(middle = 7L) ?(parent = 7L) ?(leaf = 7L) () = [
  0x1000L, Demo.page [0, Int64.logor 0x2000L upper];
  0x2000L, Demo.page [0, Int64.logor 0x3000L middle];
  0x3000L, Demo.page [0, Int64.logor 0x4000L parent];
  0x4000L, Demo.page [0, Int64.logor 0x9000L leaf] ]

let explain capture ?(address = 0L) request =
  Paging.explain (Capture.context capture) (Capture.read capture) (virtual_address address) request

let expect_fault ?level vector code result = match result.outcome with
  | Fault f ->
      check (f.vector = vector) "fault vector";
      check (f.error_code = code) (Printf.sprintf "error code: expected %x got %x (%s)" code f.error_code f.reason);
      Option.iter (fun level -> check (f.level = Some level) "fault level") level
  | _ -> failwith "expected fault"

let expect_mapped result = match result.outcome with
  | Mapped m -> check true "mapped"; m
  | Fault f -> failwith ("unexpected fault: " ^ f.reason)
  | Incomplete reason -> failwith ("unexpected incomplete: " ^ reason)

let rejects action =
  check (try action (); false with Invalid_argument _ | Model.Limit _ -> true) "expected rejection"

let permissions () =
  for upper = 0 to 7 do
    for middle = 0 to 7 do
      for parent = 0 to 7 do
        for leaf = 0 to 7 do
          let flags x = Int64.of_int (1 lor ((x land 1) lsl 1) lor ((x land 2) lsl 1))
            |> fun bits -> if x land 4 <> 0 then Int64.logor bits Int64.min_int else bits in
          let capture = capture (tables ~upper:(flags upper) ~middle:(flags middle)
            ~parent:(flags parent) ~leaf:(flags leaf) ()) in
          let mapping = expect_mapped (Paging.walk (Capture.context capture) (Capture.read capture) (virtual_address 0L)) in
          check (mapping.permissions.writable = (upper land middle land parent land leaf land 1 <> 0)) "write accumulation";
          check (mapping.permissions.user = (upper land middle land parent land leaf land 2 <> 0)) "user accumulation";
          check (mapping.permissions.executable = ((upper lor middle lor parent lor leaf) land 4 = 0)) "nx accumulation"
        done
      done
    done
  done;
  let c = capture (tables ~parent:5L ()) in
  expect_fault ~level:2 14 3 (explain c (supervisor Write));
  expect_fault ~level:2 14 7 (explain c (user Write));
  let context = { Demo.context with registers = { Demo.context.registers with cr0 = 0x80000001L } } in
  ignore (expect_mapped (explain (capture ~context (tables ~parent:5L ())) (supervisor Write)));
  expect_fault 14 5 (explain (capture (tables ~upper:3L ())) (user Read));
  expect_fault 14 17 (explain (capture (tables ~parent:0x8000000000000007L ())) (supervisor Execute));
  let context = { Demo.context with registers = { Demo.context.registers with cr4 = 0x100020L } } in
  expect_fault 14 17 (explain (capture ~context (tables ())) (supervisor Execute));
  let context = { Demo.context with registers = { Demo.context.registers with cr4 = 0x200020L } } in
  let c = capture ~context (tables ()) in
  expect_fault 14 1 (explain c (supervisor Read));
  expect_fault 14 3 (explain c (supervisor Write));
  ignore (expect_mapped (explain c { access = Write; privilege = Supervisor; ac = true }));
  ignore (expect_mapped (explain c (supervisor Execute)))

let translation () =
  let c = capture (tables ()) in
  let m = expect_mapped (explain c ~address:0xabcL (supervisor Read)) in
  check (Address.Physical.to_int64 m.physical_address = 0x9abcL) "4k offset";
  expect_fault 13 0 (explain c ~address:0x0000800000000000L (supervisor Read));
  expect_fault 13 0 (explain c ~address:0xffff7fffffffffffL (supervisor Read));
  let c = capture [0x1000L, Demo.page [511, 0x2007L]; 0x2000L, Demo.page [511, 0x3007L];
    0x3000L, Demo.page [511, 0x4007L]; 0x4000L, Demo.page [511, 0x9007L]] in
  let m = expect_mapped (explain c ~address:(-1L) (supervisor Read)) in
  check (Address.Physical.to_int64 m.physical_address = 0x9fffL) "upper canonical address";
  let regions = Paging.enumerate (Capture.context c) (Capture.read c) in
  check (List.length regions = 1 && (List.hd regions).start = 0xfffffffffffff000L) "upper enumeration";
  let c = capture [0x1000L, Demo.page [0, 0x2007L]; 0x2000L, Demo.page [0, 0x3007L];
    0x3000L, Demo.page [0, 0x201087L]] in
  let m = expect_mapped (explain c ~address:0x1fffffL (supervisor Read)) in
  check (m.size = 0x200000L && Address.Physical.to_int64 m.physical_address = 0x3fffffL) "2m pat and offset";
  let c = capture [0x1000L, Demo.page [0, 0x2007L]; 0x2000L, Demo.page [0, 0x40001087L]] in
  let m = expect_mapped (explain c ~address:0x3fffffffL (supervisor Read)) in
  check (m.size = 0x40000000L && Address.Physical.to_int64 m.physical_address = 0x7fffffffL) "1g pat and offset";
  let c = capture (tables ~leaf:0x87L ()) in
  ignore (expect_mapped (explain c (supervisor Read)));
  let context = { Demo.context with registers = { Demo.context.registers with cr3 = 0x1abcL; cr4 = 0x20020L } } in
  ignore (expect_mapped (explain (capture ~context (tables ())) (supervisor Read)))

let invalid () =
  expect_fault ~level:4 14 9 (explain (capture (tables ~upper:0x87L ())) (supervisor Read));
  expect_fault ~level:1 14 9 (explain (capture (tables ~leaf:0x1000000000007L ())) (supervisor Read));
  let context = { Demo.context with registers = { Demo.context.registers with efer = 0x500L } } in
  expect_fault 14 9 (explain (capture ~context (tables ~leaf:0x8000000000000007L ())) (supervisor Read));
  let context = { Demo.context with features = { Demo.context.features with gb_pages = false } } in
  let c = capture ~context [0x1000L, Demo.page [0, 0x2007L]; 0x2000L, Demo.page [0, 0x87L]] in
  expect_fault 14 9 (explain c (supervisor Read));
  let c = capture [0x1000L, Demo.page [0, 0x2007L]; 0x2000L, Demo.page [0, 0x3007L]; 0x3000L, Demo.page [0, 0x2087L]] in
  expect_fault 14 9 (explain c (supervisor Read));
  let c = capture (tables ~parent:0L ()) in
  expect_fault ~level:2 14 0 (explain c (supervisor Read));
  let c = capture (tables ~parent:0L ~upper:1L ()) in
  expect_fault ~level:2 14 6 (explain c (user Write));
  List.iter (fun bit -> rejects (fun () ->
    Model.validate { Demo.context with registers = { Demo.context.registers with cr4 = Int64.logor 0x20L (Int64.shift_left 1L bit) } })) [12; 22; 23; 24];
  let context = { Demo.context with registers = { Demo.context.registers with cr3 = 0x1abcL } } in
  ignore (expect_mapped (explain (capture ~context (tables ())) (supervisor Read)));
  rejects (fun () -> ignore (Address.parse "-1"));
  rejects (fun () -> ignore (Address.parse "18446744073709551616"));
  check (Address.parse "18446744073709551615" = -1L) "unsigned decimal parsing"

let incomplete () =
  let c = capture [0x1000L, Demo.page [0, 0x2007L]] in
  check (match (explain c (supervisor Read)).outcome with Incomplete _ -> true | _ -> false) "missing table is incomplete";
  let regions = Paging.enumerate (Capture.context c) (Capture.read c) in
  check (List.length regions = 1 && (List.hd regions).length = 0x8000000000L) "missing subtree range";
  let c = Capture.make Demo.context [] in
  let regions = Paging.enumerate Demo.context (Capture.read c) in
  check (List.length regions = 2) "missing root covers both canonical halves";
  let c = Demo.capture ~after:false in
  rejects (fun () -> ignore (Paging.enumerate ~max_entries:1 Demo.context (Capture.read c)));
  rejects (fun () -> ignore (Capture.collect ~max_pages:1 Demo.context (Capture.read c)));
  let reads = ref 0 in
  let collected = Capture.collect Demo.context (fun address -> incr reads; Capture.read c address) in
  check (!reads = 5 && Capture.pages collected = 5) "capture memoises table frames"

let regions capture = Paging.enumerate (Capture.context capture) (Capture.read capture)

let diff () =
  let a = Demo.capture ~after:false and b = Demo.capture ~after:true in
  let changes = Analysis.diff (regions a) (regions b) in
  check (List.length changes = 2) "demo diff count";
  check ((List.hd changes).kinds = ["permissions"]) "parent permission diff";
  check ((List.nth changes 1).kinds = ["backing"]) "backing diff";
  check (Analysis.diff (regions a) (regions a) = []) "identity diff";
  let a = capture (tables ()) in
  let b = capture (tables ~leaf:0x67L ()) in
  check (Analysis.diff (regions a) (regions b) = []) "ignore ad by default";
  check ((List.hd (Analysis.diff ~include_ad:true (regions a) (regions b))).kinds = ["accessed_dirty"]) "include ad";
  let huge = capture [0x1000L, Demo.page [0, 0x2007L]; 0x2000L, Demo.page [0, 0x3007L]; 0x3000L, Demo.page [0, 0x87L]] in
  let small = capture [0x1000L, Demo.page [0, 0x2007L]; 0x2000L, Demo.page [0, 0x3007L];
    0x3000L, Demo.page [0, 0x4007L]; 0x4000L, Demo.page (List.init 512 (fun index -> index, Int64.logor 7L (Int64.of_int (index * 4096))))] in
  let changes = Analysis.diff (regions huge) (regions small) in
  check (List.length changes = 512 && List.for_all (fun (c : Analysis.change) -> c.kinds = ["page_size"]) changes) "huge split preserves backing";
  let partial = Capture.make Demo.context [] in
  let changes = Analysis.diff (regions partial) (regions a) in
  check (List.for_all (fun (c : Analysis.change) -> c.kinds = ["incomplete"]) changes) "incomplete is not removal"

let aliases () =
  let pairs = Analysis.aliases (regions (Demo.capture ~after:false)) in
  check (List.length pairs = 1) "demo alias";
  let pair = List.hd pairs in
  check (pair.physical = 0x9000L && pair.length = 4096L) "alias overlap";
  check (Analysis.aliases (regions (Demo.capture ~after:true)) = []) "demo resolved alias";
  let make_mapping va pa size permissions = {
    virtual_address = virtual_address va; physical_address = physical_address pa;
    size; permissions; leaf = 0L; trace = [] } in
  let writable = { unrestricted with executable = false } in
  let executable = { unrestricted with writable = false } in
  let a = make_mapping 0L 0x200000L 0x200000L executable in
  let b = make_mapping 0x800000L 0x201000L 4096L writable in
  let pairs = Analysis.aliases [
    { Paging.start = 0L; length = a.size; state = Paging.Present a };
    { Paging.start = 0x800000L; length = b.size; state = Paging.Present b } ] in
  check (List.length pairs = 1 && (List.hd pairs).physical = 0x201000L && (List.hd pairs).length = 4096L) "partial huge alias"

let codec () =
  let path = Filename.temp_file "scope" ".capture" in
  Fun.protect ~finally:(fun () -> Sys.remove path) (fun () ->
    let original = Demo.capture ~after:false in
    Capture.save path original;
    let loaded = Capture.load path in
    check (Capture.context original = Capture.context loaded) "context roundtrip";
    check (regions original = regions loaded) "table roundtrip";
    let channel = open_out_gen [Open_wronly; Open_binary] 0o600 path in
    seek_out channel 32;
    output_char channel '\255';
    close_out channel;
    rejects (fun () -> ignore (Capture.load path)));
  rejects (fun () -> ignore (Capture.make Demo.context [physical_address 0x1000L, Ok "short"]));
  rejects (fun () -> ignore (Capture.make Demo.context [physical_address 0x1001L, Ok (Demo.page [])]));
  rejects (fun () -> ignore (capture [0x1000L, Demo.page []; 0x1000L, Demo.page []]))

let generated () =
  let random = Random.State.make [|0x5c0; 0x2026|] in
  let generate () =
    let entries = List.init 64 (fun index ->
      let frame = Random.State.int random 16 in
      let flags = Int64.of_int (1 lor (Random.State.int random 4 lsl 1)) in
      let flags = if Random.State.bool random then Int64.logor flags Int64.min_int else flags in
      index, if Random.State.int random 4 = 0 then 0L else Int64.logor (Int64.of_int (frame * 4096)) flags) in
    capture [0x1000L, Demo.page [0, 0x2007L]; 0x2000L, Demo.page [0, 0x3007L];
      0x3000L, Demo.page [0, 0x4007L]; 0x4000L, Demo.page entries]
  in
  for _ = 1 to 64 do
    let a = generate () and b = generate () in
    let changes = Analysis.diff (regions a) (regions b) in
    for index = 0 to 63 do
      let address = Int64.of_int (index * 4096) in
      let state capture = match (explain capture ~address (supervisor Read)).outcome with
        | Mapped m -> Some (Paging.Present m)
        | Fault _ -> None
        | Incomplete _ -> failwith "generated graph unexpectedly incomplete"
      in
      let expected = Analysis.differences ~include_ad:false (state a) (state b) in
      let observed = List.find_opt (fun (c : Analysis.change) ->
        Address.compare address c.start >= 0 && Address.compare address (Int64.pred (Int64.add c.start c.length)) <= 0) changes
        |> Option.map (fun (c : Analysis.change) -> c.kinds) |> Option.value ~default:[] in
      check (expected = observed) "interval diff agrees with point translations"
    done;
    let mappings = regions a |> List.filter_map (fun r -> match r.Paging.state with Paging.Present m -> Some m | _ -> None) in
    let physical m = Address.Physical.to_int64 m.physical_address in
    let virtual_raw m = Address.Virtual.to_int64 m.virtual_address in
    let expected = List.concat_map (fun w -> List.filter_map (fun x ->
      if w.permissions.writable && x.permissions.executable && virtual_raw w <> virtual_raw x && physical w = physical x then
        Some (physical w, 4096L, virtual_raw w, virtual_raw x) else None) mappings) mappings |> List.sort compare in
    let actual = Analysis.aliases (regions a) |> List.map (fun (a : Analysis.alias) ->
      a.physical, a.length, virtual_raw a.writable, virtual_raw a.executable) |> List.sort compare in
    check (expected = actual) "alias sweep agrees with pairwise overlap oracle"
  done;
  let self = capture [0x1000L, Demo.page [0, 0x1007L]] in
  let reads = ref 0 in
  let closed = Capture.collect Demo.context (fun address -> incr reads; Capture.read self address) in
  check (!reads = 1 && Capture.pages closed = 1) "recursive mapping is read once across levels";
  ignore (expect_mapped (explain closed (supervisor Read)));
  let context = { Demo.context with registers = { Demo.context.registers with cr3 = 0x1000L } } in
  let exploding = capture ~context [0x1000L, Demo.page (List.init 512 (fun index -> index, 0x1007L))] in
  rejects (fun () -> ignore (Paging.enumerate ~max_entries:4096 context (Capture.read exploding)))

let imports () =
  let path = Filename.temp_file "scopeimport" "" in
  Fun.protect ~finally:(fun () -> Sys.remove path) (fun () ->
    let context = "context 0x80010001 0 0x1000 0x20 0xd00 2 0 48 1 1" in
    let write text =
      let channel = open_out_bin path in
      Fun.protect ~finally:(fun () -> close_out_noerr channel) (fun () -> output_string channel text)
    in
    List.iter (fun ending ->
      write (context ^ ending);
      let imported = Capture.import ~source:"test" path in
      check (Capture.pages imported = 0) "import accepts context at eof") [""; "\n"];
    List.iter (fun ending ->
      write (context ^ "\n" ^ String.make 16384 ' ' ^ ending);
      check (Capture.pages (Capture.import ~source:"test" path) = 0)
        "import accepts maximum line length") [""; "\n"];
    List.iter (fun ending ->
      write (context ^ "\n" ^ String.make 16385 ' ' ^ ending);
      rejects (fun () -> ignore (Capture.import ~source:"test" path))) [""; "\n"];
    write (context ^ "\n" ^ String.make (2 * 1024 * 1024) 'x');
    let allocated = Gc.allocated_bytes () in
    let rejected = try ignore (Capture.import ~source:"test" path); false with
      Invalid_argument reason -> reason = "import line exceeds 16384 bytes"
    in
    let allocated = Gc.allocated_bytes () -. allocated in
    check rejected "import rejects oversized record before parsing";
    check (allocated < 1048576.) "import rejects oversized line with bounded allocation")

let watch () =
  let base = Filename.temp_file "scopewatch" "" in
  Sys.remove base;
  let a = Demo.capture ~after:false and b = Demo.capture ~after:true in
  let switched = capture ~context:{ Demo.context with registers = { Demo.context.registers with cr3 = 0x6000L } }
    ((0x6000L, Demo.page [0, 0x2007L]) :: Demo.frames ~after:true) in
  let samples = ref [a; b; b; Capture.make Demo.context []; b; switched] in
  let events = ref [] in
  let capture () = match !samples with x :: xs -> samples := xs; x | [] -> failwith "sample exhaustion" in
  let status = Watch.run ~capture ~wait:(fun _ -> ()) ~emit:(fun event -> events := event :: !events)
    ~directory:base ~interval:0.1 ~count:6 ~retain:2 ~max_entries:10000 ~max_pairs:100
    ~include_ad:false ~scan_aliases:true ~selected:(fun _ -> true) () in
  check (status = 2) "watch remembers incomplete samples";
  let events = List.rev !events in
  check (List.map (fun (e : Watch.event) -> e.kind) events =
    ["baseline"; "change"; "sample"; "incomplete"; "sample"; "address_space"]) "watch transitions";
  check (List.length (List.nth events 1).changes = 2) "watch semantic changes";
  check ((List.hd events).mappings = 2 && (List.hd events).bytes = 8192L) "watch statistics";
  check (List.length (List.hd events).aliases = 1) "watch alias baseline";
  check (Array.length (Sys.readdir base) = 2) "watch bounded retention";
  let pair = Filename.concat base "00000006" in
  check (Capture.context (Capture.load (Filename.concat pair "before")) = Capture.context b) "watch preserves last complete baseline";
  check ((List.nth events 5).changes = []) "watch does not diff unrelated roots";
  Array.iter (fun name -> let path = Filename.concat base name in
    Array.iter (fun child -> Sys.remove (Filename.concat path child)) (Sys.readdir path);
    Unix.rmdir path) (Sys.readdir base);
  Unix.rmdir base

let () =
  permissions ();
  translation ();
  invalid ();
  incomplete ();
  diff ();
  aliases ();
  codec ();
  generated ();
  imports ();
  watch ();
  Printf.printf "%d checks passed\n" !count
