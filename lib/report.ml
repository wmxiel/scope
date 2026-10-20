open Model
open Json

let limitations = [
  "guest first-stage table state only; tlb and second-stage permissions are not observed";
  "ordinary explicit accesses only; implicit supervisor accesses and cross-page operations are not modelled";
  "pausing vcpus does not quiesce dma, device models, or other memory writers";
  "permissions describe architectural access, not speculative execution" ]

let permissions p = Object ["writable", Bool p.writable; "user", Bool p.user; "executable", Bool p.executable]

let context c =
  let r = c.registers and f = c.features in
  Object ["source", String c.source; "consistency", String c.consistency; "identity", String c.identity;
    "domid", Int c.domid; "vcpu", Int c.vcpu;
    "root", hex (Address.Physical.to_int64 (Model.root c)); "root_override", option hex c.root_override;
    "features", Object ["phys_bits", Int f.phys_bits; "nx", Bool f.nx; "gb_pages", Bool f.gb_pages];
    "registers", Object ["cr0", hex r.cr0; "cr2", hex r.cr2; "cr3", hex r.cr3; "cr4", hex r.cr4;
      "efer", hex r.efer; "rflags", hex r.rflags; "rip", hex r.rip]]

let step (s : step) = Object ["level", Int s.level; "table", hex (Address.Physical.to_int64 s.table);
  "index", Int s.index; "entry_address", hex Int64.(add (Address.Physical.to_int64 s.table) (of_int (s.index * 8)));
  "raw", hex s.raw; "effective", permissions s.effective]

let mapping (m : mapping) = Object [
  "virtual", hex (Address.Virtual.to_int64 m.virtual_address);
  "physical", hex (Address.Physical.to_int64 m.physical_address);
  "page_size", hex m.size; "permissions", permissions m.permissions; "leaf", hex m.leaf;
  "trace", List (List.map step m.trace)]

let fault f = Object ["vector", Int f.vector; "error_code", Int f.error_code;
  "reason", String f.reason; "level", option (fun n -> Int n) f.level]

let outcome = function
  | Mapped m -> Object ["status", String "mapped"; "mapping", mapping m]
  | Fault f -> Object ["status", String "fault"; "fault", fault f]
  | Incomplete reason -> Object ["status", String "incomplete"; "reason", String reason]

let state = function
  | Paging.Present m -> Object ["status", String "mapped"; "mapping", mapping m]
  | Paging.Unknown reason -> Object ["status", String "incomplete"; "reason", String reason]
  | Paging.Broken reason -> Object ["status", String "invalid"; "reason", String reason]

let region (r : Paging.region) = Object ["start", hex r.start; "length", hex r.length; "state", state r.state]

let change (c : Analysis.change) = Object ["start", hex c.start; "length", hex c.length;
  "kinds", List (List.map string c.kinds); "before", option state c.before; "after", option state c.after]

let alias (a : Analysis.alias) = Object ["physical", hex a.physical; "length", hex a.length;
  "writable", mapping a.writable; "executable", mapping a.executable]

let envelope command c complete fields = Object (
  ["schema", String "scope.report.v1"; "command", String command; "context", context c;
    "complete", Bool complete; "limitations", List (List.map string limitations)] @ fields)

let rights p = Printf.sprintf "r%c%c/%c" (if p.writable then 'w' else '-')
  (if p.executable then 'x' else '-') (if p.user then 'u' else 's')

let print_context c =
  Printf.printf "source=%S identity=%S domid=%d vcpu=%d cr3=%s root=%s phys_bits=%d nx=%b gb_pages=%b\n"
    c.source c.identity c.domid c.vcpu (Address.hex c.registers.cr3)
    (Address.hex (Address.Physical.to_int64 (Model.root c))) c.features.phys_bits c.features.nx c.features.gb_pages;
  Printf.printf "consistency=%S\n" c.consistency;
  Printf.printf "scope=guest-table-state tlb=unobserved second-stage=unobserved\n"

let print_step (s : step) =
  Printf.printf "l%d table=%s index=%03x raw=%s effective=%s\n" s.level
    (Address.hex (Address.Physical.to_int64 s.table)) s.index (Address.hex s.raw) (rights s.effective)

let print_mapping m = Printf.printf "%s -> %s size=%s %s\n"
  (Address.hex (Address.Virtual.to_int64 m.virtual_address))
  (Address.hex (Address.Physical.to_int64 m.physical_address)) (Address.hex m.size) (rights m.permissions)

let print_result result =
  List.iter print_step result.trace;
  match result.outcome with
  | Mapped m -> print_mapping m
  | Fault f -> Printf.printf "fault vector=%d error=0x%x level=%s reason=%s\n" f.vector f.error_code
      (match f.level with None -> "-" | Some n -> string_of_int n) f.reason
  | Incomplete reason -> Printf.printf "incomplete reason=%s\n" reason

let print_region (r : Paging.region) = match r.state with
  | Paging.Present m -> print_mapping m
  | Paging.Unknown reason -> Printf.printf "%s length=%s incomplete=%s\n" (Address.hex r.start) (Address.hex r.length) reason
  | Paging.Broken reason -> Printf.printf "%s length=%s invalid=%s\n" (Address.hex r.start) (Address.hex r.length) reason
