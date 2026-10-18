A version 1 capture contains a fixed header, three metadata strings and the table frames below the selected root. Integers are little-endian and no OCaml values are marshalled, so the reader can check lengths and tags before constructing a paging context.

## Header

```text
offset  bytes  encoding  field
0       8      bytes     53 43 4f 50 45 00 01 0a
8       4      u32       domid
12      4      u32       vcpu
16      4      u32       physical-address width
20      4      u32       feature flags
24      56     7 * u64   cr0 cr2 cr3 cr4 efer rflags rip
80      4      u32       root-override tag
84      8      u64       root-override value

feature flags
  bit 0 = nx
  bit 1 = 1 gib pages
  other bits = rejected

root override
  tag 0 = use saved cr3, value must be zero
  tag 1 = select value as the raw root, retain saved cr3
  other tags = rejected
```

## Payload

```text
string       = u32 byte-length, byte-length bytes
metadata     = string source, string consistency, string domain-identity
frame        = u64 guest-physical-address, u32 tag, frame-payload
tag 0        = 4096 bytes of table contents
tag 1        = string read-error
frames       = u32 count, count frame records
file         = header, metadata, frames, 16-byte digest
digest       = raw md5 of every preceding byte

bounds
  runtime                 = 64-bit
  physical width          = 32..52
  string length           <= 4096
  frame count             <= 65536
  file length             <= 280000000
  frame alignment         = 4096
  duplicate frames        = rejected
  unknown frame tags      = rejected
  out-of-width addresses  = rejected
  trailing payload bytes  = rejected
  checksum mismatch       = rejected
```

MD5 detects accidental corruption and does not authenticate a capture. Writes go through a mode-0600 temporary file beside the destination, followed by `fsync` and rename, but the directory itself is not synchronised and the rename may therefore be lost after a host crash.

## Import

```text
command
  scope import TRANSCRIPT OUTPUT [--source TEXT]

records
  context CR0 CR2 CR3 CR4 EFER RFLAGS RIP PHYS_BITS NX GB_PAGES
  page ADDRESS HEX
  missing ADDRESS REASON

grammar
  addresses and registers = unsigned decimal or 0x-prefixed hex
  phys_bits               = decimal
  nx and gb_pages         = 0 or 1
  hex                     = 8192 hex digits in ascending byte order
  field separator         = ordinary spaces
  record separator        = newline
  reason                  = rest of line, may be empty
  context count           = exactly one, may follow frame records
  duplicate frames        = rejected
  unknown records         = rejected
  line length             <= 16384 bytes
  input length            <= 840000000 bytes
  imported root override  = none
  imported domid and vcpu  = 0
```

## Reports

```text
schema               = scope.report.v1
addresses and sizes  = hexadecimal strings
complete             = completeness of the requested analysis
info                  = checks the selected table graph
walk                  = structural fault bits, no assumed access or privilege
explain               = error code for the explicit request
ac                    = captured rflags unless --ac overrides it
error_code_scope      = structural_bits_only or request

diff
  intervals            = disjoint virtual ranges
  mapping states       = values and paths at the interval start
  leaf sizes           = original sizes retained
  huge-page split      = potentially one record per smaller leaf
  unreadable subtree   = incomplete, never treated as absent

limits
  traversal budget     = abort before emitting a partial report
  alias budget         = abort before emitting a partial report
  error stream         = stderr, structured when --json is selected
  result stream        = stdout
  exit 0               = complete, no fault or finding
  exit 1               = predicted fault, invalid table, alias or diff
  exit 2               = incomplete or operational failure
  exit 64              = usage error
```
