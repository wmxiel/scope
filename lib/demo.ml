open Model

let context = {
  registers = { cr0 = 0x80010001L; cr2 = 0L; cr3 = 0x1000L; cr4 = 0x20L;
    efer = 0xd00L; rflags = 2L; rip = 0L };
  features = { phys_bits = 48; nx = true; gb_pages = true };
  root_override = None;
  source = "synthetic fixture"; consistency = "immutable synthetic tables";
  identity = "scope-demo"; domid = 0; vcpu = 0;
}

let page entries =
  let bytes = Bytes.make 4096 '\000' in
  List.iter (fun (index, entry) -> Bytes.set_int64_le bytes (index * 8) entry) entries;
  Bytes.to_string bytes

let frames ~after = [
  0x1000L, page [0, 0x2007L];
  0x2000L, page [0, 0x3007L];
  0x3000L, page [2, (if after then 0x4003L else 0x4001L); 4, 0x5003L];
  0x4000L, page [0, 0x9003L];
  0x5000L, page [0, Int64.logor 0x8000000000000000L (if after then 0xa003L else 0x9003L)] ]

let capture ~after = Capture.make context (List.map (fun (address, bytes) -> Address.Physical.of_int64 address, Ok bytes) (frames ~after))

let write directory =
  if not (Sys.file_exists directory) then Unix.mkdir directory 0o755;
  Capture.save (Filename.concat directory "before") (capture ~after:false);
  Capture.save (Filename.concat directory "after") (capture ~after:true)
