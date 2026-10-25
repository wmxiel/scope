#include <stdint.h>
#include <stddef.h>

static uint64_t root[512] __attribute__((aligned(4096)));
static uint64_t directory[512] __attribute__((aligned(4096)));
static uint64_t middle[512] __attribute__((aligned(4096)));
static uint64_t table[512] __attribute__((aligned(4096)));
static uint8_t payload[4096] __attribute__((aligned(4096)));

volatile uint64_t recovery_stack;
volatile uint64_t recovery_address;
volatile uint64_t observed_vector;
volatile uint64_t observed_error;

extern void probe(int access, uint64_t address);
extern void pagefault(void);
extern void protection(void);
extern void completed(void);
extern void probe_user(int access, uint64_t address);
extern uint64_t gdt[];

struct gate {
  uint16_t low;
  uint16_t selector;
  uint8_t ist;
  uint8_t flags;
  uint16_t middle;
  uint32_t high;
  uint32_t reserved;
} __attribute__((packed));

static struct gate idt[256];
static int phys_bits;
static int nx;
static int gb_pages;
static int user_mode;
static uint64_t root_bits;

static struct {
  uint32_t reserved;
  uint64_t rsp[3];
  uint64_t reserved1;
  uint64_t ist[7];
  uint64_t reserved2;
  uint16_t reserved3;
  uint16_t iomap;
} __attribute__((packed)) tss;

static void put(char c) {
  __asm__ volatile("outb %0, $0xe9" : : "a"(c));
}

static void text(const char *s) {
  while (*s) put(*s++);
}

static void hex(uint64_t n) {
  text("0x");
  for (int shift = 60; shift >= 0; shift -= 4) put("0123456789abcdef"[(n >> shift) & 15]);
}

static void decimal(int n) {
  if (n >= 10) decimal(n / 10);
  put('0' + n % 10);
}

static uint64_t cr0(void) {
  uint64_t value;
  __asm__ volatile("mov %%cr0, %0" : "=r"(value));
  return value;
}

static uint64_t cr4(void) {
  uint64_t value;
  __asm__ volatile("mov %%cr4, %0" : "=r"(value));
  return value;
}

static void set_cr0(uint64_t value) {
  __asm__ volatile("mov %0, %%cr0" : : "r"(value) : "memory");
}

static void set_cr4(uint64_t value) {
  __asm__ volatile("mov %0, %%cr4" : : "r"(value) : "memory");
}

static uint64_t efer(void) {
  uint32_t low, high;
  __asm__ volatile("rdmsr" : "=a"(low), "=d"(high) : "c"(0xc0000080));
  return (uint64_t)high << 32 | low;
}

static void set_efer(uint64_t value) {
  __asm__ volatile("wrmsr" : : "a"((uint32_t)value), "d"((uint32_t)(value >> 32)), "c"(0xc0000080));
}

static void set_ac(int enabled) {
  uint64_t flags;
  __asm__ volatile("pushfq; pop %0" : "=r"(flags));
  flags = enabled ? flags | (1u << 18) : flags & ~(1u << 18);
  __asm__ volatile("push %0; popfq" : : "r"(flags) : "cc", "memory");
}

static void flush(void) {
  __asm__ volatile("mov %0, %%cr3" : : "r"((uint64_t)root | root_bits) : "memory");
}

static void gate(int vector, void (*handler)(void)) {
  uint64_t address = (uint64_t)handler;
  idt[vector] = (struct gate){address, 0x18, 0, 0x8e, address >> 16, address >> 32, 0};
}

static void reset(void) {
  __asm__ volatile("mov %0, %%cr3" : : "r"(0x70000ull) : "memory");
  set_cr4(0x20);
  set_cr0(cr0() | (1u << 16));
  set_efer(efer() | (1u << 11));
  set_ac(0);
  user_mode = 0;
  root_bits = 0;
  for (int i = 0; i < 512; i++) root[i] = directory[i] = middle[i] = table[i] = 0;
  root[0] = (uint64_t)directory | 7;
  directory[0] = (uint64_t)middle | 7;
  middle[0] = 0x83;
  middle[2] = (uint64_t)table | 7;
  table[0] = (uint64_t)payload | 3;
  payload[0] = 0xc3;
  flush();
}

static void page(uint64_t *frame) {
  text("page ");
  hex((uint64_t)frame);
  put(' ');
  const uint8_t *bytes = (const uint8_t *)frame;
  for (int i = 0; i < 4096; i++) {
    put("0123456789abcdef"[bytes[i] >> 4]);
    put("0123456789abcdef"[bytes[i] & 15]);
  }
  put('\n');
}

static void run(const char *name, int access, uint64_t address) {
  uint64_t flags, current_cr2, current_cr3;
  flush();
  __asm__ volatile("pushfq; pop %0" : "=r"(flags));
  __asm__ volatile("mov %%cr2, %0" : "=r"(current_cr2));
  __asm__ volatile("mov %%cr3, %0" : "=r"(current_cr3));
  text("begin "); text(name); put(' '); decimal(access); put(' '); hex(address);
  text(user_mode ? " user\n" : " supervisor\n");
  text("context "); hex(cr0()); put(' '); hex(current_cr2); put(' '); hex(current_cr3);
  put(' '); hex(cr4()); put(' '); hex(efer()); put(' '); hex(flags); text(" 0x0 ");
  decimal(phys_bits); put(' '); decimal(nx); put(' '); decimal(gb_pages); put('\n');
  page(root); page(directory); page(middle); page(table);
  observed_vector = 0;
  observed_error = 0;
  flush();
  if (user_mode) probe_user(access, address);
  else probe(access, address);
  text("observed "); decimal(observed_vector); put(' '); decimal(observed_error); put('\n');
  text("end\n");
}

static void run_user(const char *name, int access) {
  middle[0] |= 4;
  user_mode = 1;
  run(name, access, 0x400000);
}

void guest(void) {
  uint32_t a, b, c, d;
  __asm__ volatile("cpuid" : "=a"(a), "=b"(b), "=c"(c), "=d"(d) : "a"(0x80000008), "c"(0));
  phys_bits = a & 255;
  __asm__ volatile("cpuid" : "=a"(a), "=b"(b), "=c"(c), "=d"(d) : "a"(0x80000001), "c"(0));
  nx = (d >> 20) & 1;
  gb_pages = (d >> 26) & 1;
  gate(13, protection);
  gate(14, pagefault);
  gate(0x80, completed);
  idt[0x80].flags = 0xee;
  tss.rsp[0] = 0x88000;
  tss.iomap = sizeof(tss);
  uint64_t base = (uint64_t)&tss;
  gdt[6] = (sizeof(tss) - 1) | ((base & 0xffffff) << 16) | (0x89ull << 40) | ((base >> 24) << 56);
  gdt[7] = base >> 32;
  __asm__ volatile("ltr %0" : : "r"((uint16_t)0x30));
  struct { uint16_t limit; uint64_t base; } __attribute__((packed)) idtr = {sizeof(idt) - 1, (uint64_t)idt};
  __asm__ volatile("lidt %0" : : "m"(idtr));
  reset(); run("read", 0, 0x400000);
  reset(); run("write", 1, 0x400000);
  reset(); run("execute", 2, 0x400000);
  reset(); middle[2] &= ~2ull; run("parent", 1, 0x400000);
  reset(); middle[2] &= ~2ull; set_cr0(cr0() & ~(1u << 16)); run("wp", 1, 0x400000);
  reset(); table[0] |= 1ull << 63; run("nx", 2, 0x400000);
  reset(); middle[2] |= 1ull << 63; run("ancestor", 2, 0x400000);
  reset(); table[0] = 0; run("absent", 0, 0x400000);
  reset(); table[0] = 0; run("absentwrite", 1, 0x400000);
  reset(); table[0] = 0; run("absentfetch", 2, 0x400000);
  reset(); table[0] |= 1ull << phys_bits; run("reserved", 0, 0x400000);
  reset(); table[0] |= 1ull << 63; set_efer(efer() & ~(1u << 11)); run("nxe", 0, 0x400000);
  reset(); middle[2] = 0x2083; run("alignment", 0, 0x400000);
  reset(); middle[2] = 0x1083; run("huge", 0, 0x401000);
  reset(); directory[1] = 0x83; run("giga", 0, 0x40001000);
  reset(); table[0] |= 0x80; run("pat", 0, 0x400000);
  reset(); root[1] = 0x83; run("pml", 0, 0x8000000000);
  reset(); run("canonical", 0, 0x800000000000);
  reset(); table[0] |= 4; set_cr4(cr4() | (1u << 20)); run("smep", 2, 0x400000);
  reset(); table[0] |= 4; set_cr4(cr4() | (1u << 21)); run("smap", 0, 0x400000);
  reset(); table[0] |= 4; set_cr4(cr4() | (1u << 21)); run("smapwrite", 1, 0x400000);
  reset(); table[0] |= 4; set_cr4(cr4() | (1u << 21)); set_ac(1); run("ac", 1, 0x400000);
  reset(); middle[2] &= ~2ull; table[0] = 0; run("precedence", 1, 0x400000);
  reset(); run_user("userdenied", 0);
  reset(); table[0] |= 4; run_user("userread", 0);
  reset(); table[0] |= 4; run_user("userwrite", 1);
  reset(); table[0] |= 4; run_user("userfetch", 2);
  reset(); table[0] |= 4; middle[2] &= ~2ull; set_cr0(cr0() & ~(1u << 16)); run_user("userwp", 1);
  reset(); table[0] |= (1ull << 63) | 4; run_user("usernx", 2);
  reset(); root_bits = 0xabc; run("rootbits", 0, 0x400000);
  reset(); set_cr4(cr4() | (1u << 17)); root_bits = 0xabc; run("pcid", 0, 0x400000);
  text("done\n");
  __asm__ volatile("outl %0, $0xf4" : : "a"(0x10));
  for (;;) __asm__ volatile("hlt");
}
