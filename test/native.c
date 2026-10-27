#include <xenctrl.h>
#include <xenforeignmemory.h>
#include <xentoollog.h>
#include <xen/hvm/save.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>

static int references;
static int calls;
static int samples;

static int failing(const char *name) {
  const char *failure = getenv("SCOPE_TEST_FAILURE");
  return failure && strcmp(failure, name) == 0;
}

static void record(const char *name) {
  const char *path = getenv("SCOPE_TEST_LOG");
  if (!path) abort();
  FILE *stream = fopen(path, "a");
  if (!stream) abort();
  fprintf(stream, "%s %d\n", name, references);
  if (fclose(stream)) abort();
}

static void diagnostic(xentoollog_logger *logger, const char *format, ...) {
  va_list arguments;
  va_start(arguments, format);
  if (logger) logger->vmessage(logger, XTL_ERROR, EACCES, "mock", format, arguments);
  else vfprintf(stderr, format, arguments);
  va_end(arguments);
}

xc_interface *xc_interface_open(xentoollog_logger *logger, xentoollog_logger *builder, unsigned flags) {
  (void)logger; (void)builder; (void)flags;
  references = getenv("SCOPE_TEST_PAUSED") ? 1 : 0;
  calls = 0;
  samples++;
  record("open");
  if (failing("logged")) { diagnostic(logger, "mock diagnostic\n"); return NULL; }
  return failing("open") ? NULL : (xc_interface *)1;
}

int xc_interface_close(xc_interface *control) {
  (void)control;
  record("close");
  return 0;
}

int xc_domain_getinfolist(xc_interface *control, uint32_t domain, unsigned count, xc_domaininfo_t *info) {
  (void)control; (void)count;
  calls++;
  if (failing("info")) return -1;
  memset(info, 0, sizeof(*info));
  info->domain = domain;
  info->max_vcpu_id = 3;
  info->flags = XEN_DOMINF_hvm_guest | (references ? XEN_DOMINF_paused : 0);
  if (failing("identity") && calls > 2) info->handle[0] = 1;
  return 1;
}

int xc_domain_pause(xc_interface *control, uint32_t domain) {
  (void)control; (void)domain;
  if (failing("pause")) return -1;
  references++;
  record("pause");
  if (failing("opensignal")) raise(SIGTERM);
  return 0;
}

int xc_domain_unpause(xc_interface *control, uint32_t domain) {
  (void)control; (void)domain;
  if (failing("unpause")) { record("unpausefailed"); return -1; }
  references--;
  record("unpause");
  return references < 0 ? -1 : 0;
}

int xc_domain_hvm_getcontext_partial(xc_interface *control, uint32_t domain, uint16_t type,
                                    uint16_t instance, void *buffer, uint32_t size) {
  (void)control; (void)domain; (void)type; (void)instance;
  record("registers");
  if (failing("signal")) raise(SIGTERM);
  if (failing("registers")) return -1;
  if (size < sizeof(struct hvm_hw_cpu)) abort();
  struct hvm_hw_cpu *cpu = buffer;
  memset(cpu, 0, sizeof(*cpu));
  cpu->cr0 = 0x80010001;
  cpu->cr3 = 0x1000;
  if (getenv("SCOPE_TEST_WATCH") && samples >= 4) cpu->cr3 = 0x6000;
  cpu->cr4 = 0x20;
  cpu->msr_efer = 0xd00;
  cpu->rflags = 2;
  return 0;
}

xenforeignmemory_handle *xenforeignmemory_open(struct xentoollog_logger *logger, unsigned flags) {
  (void)logger; (void)flags;
  record("foreignopen");
  return failing("foreignopen") ? NULL : (xenforeignmemory_handle *)2;
}

int xenforeignmemory_close(xenforeignmemory_handle *memory) {
  (void)memory;
  record("foreignclose");
  return 0;
}

void *xenforeignmemory_map(xenforeignmemory_handle *memory, uint32_t domain, int protection,
                           size_t count, const xen_pfn_t *frames, int *errors) {
  (void)memory; (void)domain; (void)protection;
  record("map");
  if (count != 1) abort();
  if (failing("map")) { errno = EACCES; return NULL; }
  uint64_t *page = calloc(512, sizeof(*page));
  if (!page) abort();
  *errors = failing("page") ? EACCES : 0;
  switch (frames[0]) {
    case 1: case 6: page[0] = 0x2007; break;
    case 2: page[0] = 0x3007; break;
    case 3: page[2] = 0x4001; page[4] = 0x5003; break;
    case 4: page[0] = 0x9003; break;
    case 5: page[0] = getenv("SCOPE_TEST_WATCH") && samples >= 2 ? 0x800000000000a003ull : 0x8000000000009003ull; break;
    default: free(page); errno = ENOENT; return NULL;
  }
  return page;
}

int xenforeignmemory_unmap(xenforeignmemory_handle *memory, void *address, size_t count) {
  (void)memory; (void)count;
  record("unmap");
  if (failing("unmap")) return -1;
  free(address);
  return 0;
}
