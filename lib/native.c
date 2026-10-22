#define _GNU_SOURCE
#include <caml/mlvalues.h>
#include <caml/memory.h>
#include <caml/alloc.h>
#include <caml/custom.h>
#include <caml/fail.h>
#include <stdbool.h>
#include <stdint.h>
#include <string.h>
#include <stdio.h>

#if defined(__has_include)
#if __has_include(<xenctrl.h>) && __has_include(<xenforeignmemory.h>)
#define SCOPE_XEN 1
#endif
#endif

#ifdef SCOPE_XEN
#include <dlfcn.h>
#include <errno.h>
#include <sys/mman.h>
#include <xenctrl.h>
#include <xenforeignmemory.h>
#include <xentoollog.h>
#include <xen/hvm/save.h>

static void quiet_message(xentoollog_logger *logger, xentoollog_level level,
                          int error, const char *context, const char *format, va_list arguments) {
  (void)logger; (void)level; (void)error; (void)context; (void)format; (void)arguments;
}

static void quiet_destroy(xentoollog_logger *logger) {
  (void)logger;
}

static xentoollog_logger quiet_logger = {
  .vmessage = quiet_message,
  .progress = NULL,
  .destroy = quiet_destroy
};

struct api {
  void *control;
  void *foreign;
  __typeof__(&xc_interface_open) control_open;
  __typeof__(&xc_interface_close) control_close;
  __typeof__(&xc_domain_getinfolist) info;
  __typeof__(&xc_domain_pause) pause;
  __typeof__(&xc_domain_unpause) unpause;
  __typeof__(&xc_domain_hvm_getcontext_partial) context;
  __typeof__(&xenforeignmemory_open) foreign_open;
  __typeof__(&xenforeignmemory_close) foreign_close;
  __typeof__(&xenforeignmemory_map) map;
  __typeof__(&xenforeignmemory_unmap) unmap;
};

static struct api api;

static bool load_api(void) {
  if (api.control && api.foreign) return true;
  api.control = dlopen("libxenctrl.so", RTLD_NOW | RTLD_LOCAL);
  api.foreign = dlopen("libxenforeignmemory.so", RTLD_NOW | RTLD_LOCAL);
  if (!api.control || !api.foreign) goto failed;
#define LOAD(member, library, symbol) \
  do { *(void **)(&api.member) = dlsym(api.library, symbol); if (!api.member) goto failed; } while (0)
  LOAD(control_open, control, "xc_interface_open");
  LOAD(control_close, control, "xc_interface_close");
  LOAD(info, control, "xc_domain_getinfolist");
  LOAD(pause, control, "xc_domain_pause");
  LOAD(unpause, control, "xc_domain_unpause");
  LOAD(context, control, "xc_domain_hvm_getcontext_partial");
  LOAD(foreign_open, foreign, "xenforeignmemory_open");
  LOAD(foreign_close, foreign, "xenforeignmemory_close");
  LOAD(map, foreign, "xenforeignmemory_map");
  LOAD(unmap, foreign, "xenforeignmemory_unmap");
#undef LOAD
  return true;
failed:
  if (api.control) dlclose(api.control);
  if (api.foreign) dlclose(api.foreign);
  memset(&api, 0, sizeof(api));
  return false;
}

struct session {
  xc_interface *control;
  xenforeignmemory_handle *foreign;
  uint32_t domid;
  uint16_t vcpu;
  bool owned_pause;
  void *mapping;
  xen_domain_handle_t identity;
};

static bool inspect(struct session *s, xc_domaininfo_t *info) {
  return api.info(s->control, s->domid, 1, info) == 1 && info->domain == s->domid &&
    memcmp(info->handle, s->identity, sizeof(s->identity)) == 0;
}

static int release(struct session *s) {
  int failed = 0;
  if (s->mapping) {
    if (api.unmap(s->foreign, s->mapping, 1) != 0) failed = 1;
    s->mapping = NULL;
  }
  if (s->owned_pause) {
    xc_domaininfo_t info;
    if (!inspect(s, &info) || api.unpause(s->control, s->domid) != 0) failed = 1;
    s->owned_pause = false;
  }
  if (s->foreign && api.foreign_close(s->foreign) != 0) failed = 1;
  if (s->control && api.control_close(s->control) != 0) failed = 1;
  s->foreign = NULL;
  s->control = NULL;
  return failed;
}

static void finalise(value block) {
  struct session *s = Data_custom_val(block);
  if (release(s)) fprintf(stderr, "scope: xen cleanup failed; inspect domain pause state\n");
}

static struct custom_operations operations = {
  .identifier = "scope.xen.session.v1",
  .finalize = finalise,
  .compare = custom_compare_default,
  .hash = custom_hash_default,
  .serialize = custom_serialize_default,
  .deserialize = custom_deserialize_default,
  .compare_ext = custom_compare_ext_default,
  .fixed_length = custom_fixed_length_default
};

static void check(struct session *s) {
  xc_domaininfo_t info;
  if (!s->control) caml_failwith("xen session is closed");
  if (!inspect(s, &info)) caml_failwith("domain identity changed or domain disappeared");
  if (!(info.flags & XEN_DOMINF_paused)) caml_failwith("domain is no longer paused");
}

CAMLprim value scope_xen_available(value unit) {
  CAMLparam1(unit);
  CAMLreturn(Val_bool(load_api()));
}

CAMLprim value scope_xen_open(value domain, value vcpu, value pause) {
  CAMLparam3(domain, vcpu, pause);
  CAMLlocal1(block);
  if (!load_api()) caml_failwith("cannot load xen control and foreign memory libraries");
  block = caml_alloc_custom(&operations, sizeof(struct session), 0, 1);
  struct session *s = Data_custom_val(block);
  memset(s, 0, sizeof(*s));
  s->domid = Int_val(domain);
  s->vcpu = Int_val(vcpu);
  s->control = api.control_open(&quiet_logger, &quiet_logger, 0);
  if (!s->control) caml_failwith("cannot open xen control interface");
  xc_domaininfo_t info;
  if (api.info(s->control, s->domid, 1, &info) != 1 || info.domain != s->domid ||
      !(info.flags & XEN_DOMINF_hvm_guest) || s->vcpu > info.max_vcpu_id) {
    release(s);
    caml_failwith("domain absent, not hvm, or vcpu outside domain range");
  }
  memcpy(s->identity, info.handle, sizeof(s->identity));
  if (Bool_val(pause)) {
    if (api.pause(s->control, s->domid) != 0) {
      release(s);
      caml_failwith("cannot acquire xen controller pause");
    }
    /* pause -> capture -> unpause, release only the reference acquired here */
    s->owned_pause = true;
  } else if (!(info.flags & XEN_DOMINF_paused)) {
    release(s);
    caml_failwith("domain must already be paused or capture must use --pause");
  }
  s->foreign = api.foreign_open(&quiet_logger, 0);
  if (!s->foreign) {
    if (release(s)) caml_failwith("foreign memory open and pause cleanup failed; inspect domain");
    caml_failwith("cannot open xen foreign memory interface");
  }
  CAMLreturn(block);
}

CAMLprim value scope_xen_registers(value block) {
  CAMLparam1(block);
  CAMLlocal4(array, number, identity, pair);
  struct session *s = Data_custom_val(block);
  check(s);
  struct hvm_hw_cpu cpu;
  if (api.context(s->control, s->domid, HVM_SAVE_CODE(CPU), s->vcpu, &cpu, sizeof(cpu)) != 0)
    caml_failwith("cannot read hvm vcpu context");
  uint64_t values[] = {cpu.cr0, cpu.cr2, cpu.cr3, cpu.cr4, cpu.msr_efer, cpu.rflags, cpu.rip};
  char encoded[sizeof(s->identity) * 2 + 1];
  for (size_t i = 0; i < sizeof(s->identity); i++) snprintf(encoded + i * 2, 3, "%02x", s->identity[i]);
  array = caml_alloc(7, 0);
  for (int i = 0; i < 7; i++) Store_field(array, i, Val_unit);
  for (int i = 0; i < 7; i++) {
    number = caml_copy_int64(values[i]);
    Store_field(array, i, number);
  }
  identity = caml_copy_string(encoded);
  pair = caml_alloc_tuple(2);
  Store_field(pair, 0, array);
  Store_field(pair, 1, identity);
  CAMLreturn(pair);
}

CAMLprim value scope_xen_read(value block, value physical) {
  CAMLparam2(block, physical);
  CAMLlocal1(bytes);
  struct session *s = Data_custom_val(block);
  check(s);
  if (s->mapping) caml_failwith("previous foreign unmap failed");
  uint64_t address = Int64_val(physical);
  if (address & 4095) caml_invalid_argument("unaligned guest physical frame");
  xen_pfn_t frame = address >> 12;
  int error = 0;
  void *mapping = api.map(s->foreign, s->domid, PROT_READ, 1, &frame, &error);
  if (mapping && mapping != MAP_FAILED) s->mapping = mapping;
  if (!mapping || mapping == MAP_FAILED || error) {
    int saved_error = error ? error : errno;
    if (s->mapping && api.unmap(s->foreign, mapping, 1) == 0) s->mapping = NULL;
    char reason[160];
    snprintf(reason, sizeof(reason), "foreign map failed at 0x%016llx: errno=%d",
      (unsigned long long)address, saved_error);
    caml_failwith(reason);
  }
  char copy[4096];
  memcpy(copy, mapping, sizeof(copy));
  if (api.unmap(s->foreign, mapping, 1) != 0) caml_failwith("foreign unmap failed");
  s->mapping = NULL;
  bytes = caml_alloc_initialized_string(sizeof(copy), copy);
  CAMLreturn(bytes);
}

CAMLprim value scope_xen_close(value block) {
  CAMLparam1(block);
  if (release(Data_custom_val(block))) caml_failwith("xen cleanup failed; inspect domain pause state");
  CAMLreturn(Val_unit);
}

#else
CAMLprim value scope_xen_available(value unit) {
  (void)unit;
  return Val_false;
}

static void unavailable(void) {
  caml_failwith("xen capture unavailable; install xen development headers and rebuild scope");
}

CAMLprim value scope_xen_open(value domain, value vcpu, value pause) {
  (void)domain; (void)vcpu; (void)pause;
  unavailable();
  return Val_unit;
}

CAMLprim value scope_xen_registers(value block) {
  (void)block;
  unavailable();
  return Val_unit;
}

CAMLprim value scope_xen_read(value block, value address) {
  (void)block; (void)address;
  unavailable();
  return Val_unit;
}

CAMLprim value scope_xen_close(value block) {
  (void)block;
  return Val_unit;
}
#endif
