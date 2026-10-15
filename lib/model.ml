type features = { phys_bits : int; nx : bool; gb_pages : bool }

type registers = {
  cr0 : int64;
  cr2 : int64;
  cr3 : int64;
  cr4 : int64;
  efer : int64;
  rflags : int64;
  rip : int64;
}

type context = {
  registers : registers;
  root_override : int64 option;
  features : features;
  source : string;
  consistency : string;
  identity : string;
  domid : int;
  vcpu : int;
}

type permissions = { writable : bool; user : bool; executable : bool }
type access = Read | Write | Execute
type privilege = Supervisor | User
type request = { access : access; privilege : privilege; ac : bool }

type step = {
  level : int;
  table : Address.Physical.t;
  index : int;
  raw : int64;
  effective : permissions;
}

type mapping = {
  virtual_address : Address.Virtual.t;
  physical_address : Address.Physical.t;
  size : int64;
  permissions : permissions;
  leaf : int64;
  trace : step list;
}

type fault = {
  vector : int;
  error_code : int;
  reason : string;
  level : int option;
}

type outcome = Mapped of mapping | Fault of fault | Incomplete of string
type result = { trace : step list; outcome : outcome }
type reader = Address.Physical.t -> (string, string) Stdlib.result

exception Limit of string

let unrestricted = { writable = true; user = true; executable = true }

let narrow permissions raw = {
  writable = permissions.writable && Address.bit raw 1;
  user = permissions.user && Address.bit raw 2;
  executable = permissions.executable && not (Address.bit raw 63);
}

let validate context =
  let r = context.registers and f = context.features in
  let require predicate reason = if not predicate then invalid_arg reason in
  require (Sys.word_size = 64) "scope requires a 64-bit runtime";
  require (f.phys_bits >= 32 && f.phys_bits <= 52) "physical width must be between 32 and 52";
  require (Address.bit r.cr0 0 && Address.bit r.cr0 31) "protected paging must be enabled";
  require (Address.bit r.cr4 5 && Address.bit r.efer 10) "only ia-32e paging is supported";
  require (not (Address.bit r.cr4 12)) "five-level paging is unsupported";
  require (not (Address.bit r.cr4 22 || Address.bit r.cr4 24)) "protection keys are unsupported";
  require (not (Address.bit r.cr4 23)) "cet is unsupported";
  require (not (Address.bit r.cr4 27)) "linear address space separation is unsupported";
  require (not (Address.bit r.cr4 28)) "supervisor linear address masking is unsupported";
  require (not (Address.bit r.efer 11) || f.nx) "nxe requires the guest nx feature";
  let validate_root root =
    require (Int64.logand root (Int64.lognot (Address.mask f.phys_bits)) = 0L)
      "cr3 exceeds the physical width or uses unsupported address masking"
  in
  validate_root r.cr3;
  Option.iter validate_root context.root_override;
  require (context.domid >= 0 && context.vcpu >= 0) "negative domain or vcpu"

let root context = Address.Physical.of_int64
  (Address.align (Option.value context.root_override ~default:context.registers.cr3) 12)
let access_name = function Read -> "read" | Write -> "write" | Execute -> "execute"
let privilege_name = function Supervisor -> "supervisor" | User -> "user"

let context_changes before after =
  let a = before.registers and b = after.registers in
  List.filter_map (fun (changed, field) -> if changed then Some field else None) [
    (a.cr0 <> b.cr0, "cr0"); (a.cr3 <> b.cr3, "cr3"); (a.cr4 <> b.cr4, "cr4");
    (root before <> root after, "root");
    (a.efer <> b.efer, "efer"); (Address.bit a.rflags 18 <> Address.bit b.rflags 18, "ac");
    (before.features.phys_bits <> after.features.phys_bits, "phys_bits");
    (before.features.nx <> after.features.nx, "nx");
    (before.features.gb_pages <> after.features.gb_pages, "gb_pages") ]
