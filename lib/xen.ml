type session

external available : unit -> bool = "scope_xen_available"
external open_domain : int -> int -> bool -> session = "scope_xen_open"
external registers : session -> int64 array * string = "scope_xen_registers"
external read_page : session -> int64 -> string = "scope_xen_read"
external close : session -> unit = "scope_xen_close"

let capture ~domid ~vcpu ~pause ~features ~root:override_root ~max_pages =
  if domid < 1 || domid >= 0x7ff0 then invalid_arg "capture requires an ordinary nonzero domain id";
  if vcpu < 0 || vcpu > 65535 then invalid_arg "vcpu outside xen context range";
  let signals = [Sys.sigint; Sys.sigterm] in
  let original_mask = Unix.sigprocmask Unix.SIG_BLOCK signals in
  let session = try open_domain domid vcpu pause with exn ->
    ignore (Unix.sigprocmask Unix.SIG_SETMASK original_mask);
    raise exn
  in
  let release () =
    let mask = Unix.sigprocmask Unix.SIG_BLOCK signals in
    Fun.protect ~finally:(fun () -> ignore (Unix.sigprocmask Unix.SIG_SETMASK mask)) (fun () -> close session)
  in
  Fun.protect ~finally:release (fun () ->
    ignore (Unix.sigprocmask Unix.SIG_SETMASK original_mask);
    let values, identity = registers session in
    let open Model in
    let registers = { cr0 = values.(0); cr2 = values.(1);
      cr3 = values.(2);
      cr4 = values.(3); efer = values.(4); rflags = values.(5); rip = values.(6) } in
    let context = { registers; features; domid; vcpu; identity; root_override = override_root;
      source = "xen hvm; operator-supplied guest cpuid profile";
      consistency = (if pause then "controller pause held during table capture; external writers not quiesced"
        else "observed paused on reads; no owned pause; external writers not quiesced") } in
    let reader address =
      try Ok (read_page session (Address.Physical.to_int64 address))
      with Failure reason -> Error reason
    in
    Capture.collect ~max_pages context reader)
