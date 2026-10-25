.section .boot,"ax"
.code16
.global boot
boot:
  cli
  xor %ax, %ax
  mov %ax, %ds
  mov %ax, %es
  mov %ax, %ss
  mov $0x7c00, %sp
  mov $packet, %si
  mov $0x42, %ah
  int $0x13
  jc stopped
  in $0x92, %al
  or $2, %al
  out %al, $0x92
  lgdt descriptor
  mov %cr0, %eax
  or $1, %eax
  mov %eax, %cr0
  ljmpl $8, $protected
stopped:
  hlt
  jmp stopped
.balign 8
packet:
  .byte 16, 0
  .word 120
  .word 0, 0x1000
  .quad 1
.global gdt
gdt:
  .quad 0
  .quad 0x00cf9a000000ffff
  .quad 0x00cf92000000ffff
  .quad 0x00af9a000000ffff
  .quad 0x00affa000000ffff
  .quad 0x00cff2000000ffff
  .quad 0, 0
descriptor:
  .word 63
  .long gdt
.org 510
.word 0xaa55

.section .text
.code32
protected:
  mov $0x10, %ax
  mov %ax, %ds
  mov %ax, %es
  mov %ax, %ss
  mov $0x90000, %esp
  cld
  mov $0x70000, %edi
  xor %eax, %eax
  mov $3072, %ecx
  rep stosl
  movl $0x71003, 0x70000
  movl $0x72003, 0x71000
  mov $0x72000, %edi
  mov $0x83, %eax
  mov $512, %ecx
1:
  mov %eax, (%edi)
  add $0x200000, %eax
  add $8, %edi
  loop 1b
  mov $0x20, %eax
  mov %eax, %cr4
  mov $0x70000, %eax
  mov %eax, %cr3
  mov $0xc0000080, %ecx
  rdmsr
  or $0x900, %eax
  wrmsr
  mov %cr0, %eax
  or $0x80010000, %eax
  mov %eax, %cr0
  ljmp $0x18, $longmode

.code64
longmode:
  mov $0x10, %ax
  mov %ax, %ds
  mov %ax, %es
  mov %ax, %ss
  mov $0x90000, %rsp
  lea __bss_start(%rip), %rdi
  lea __bss_end(%rip), %rcx
  sub %rdi, %rcx
  xor %eax, %eax
  rep stosb
  call guest
2:
  hlt
  jmp 2b

.global probe
probe:
  mov %rsp, recovery_stack(%rip)
  lea 5f(%rip), %rax
  mov %rax, recovery_address(%rip)
  test %edi, %edi
  jz 3f
  cmp $1, %edi
  je 4f
  call *%rsi
  jmp 5f
3:
  mov (%rsi), %rax
  jmp 5f
4:
  movq $0xc3, (%rsi)
5:
  ret

.global probe_user
probe_user:
  mov %rsp, recovery_stack(%rip)
  lea 9f(%rip), %rax
  mov %rax, recovery_address(%rip)
  pushq $0x2b
  pushq $0x86000
  pushq $2
  pushq $0x23
  lea 6f(%rip), %rax
  push %rax
  iretq
6:
  test %edi, %edi
  jz 7f
  cmp $1, %edi
  je 8f
  call *%rsi
  int $0x80
7:
  mov (%rsi), %rax
  int $0x80
8:
  movq $0xc3, (%rsi)
  int $0x80
9:
  ret

.global completed
completed:
  pushq $0
  jmp recover

.global pagefault
pagefault:
  movq $14, observed_vector(%rip)
  jmp recover
.global protection
protection:
  movq $13, observed_vector(%rip)
recover:
  push %rax
  mov 8(%rsp), %rax
  mov %rax, observed_error(%rip)
  mov recovery_address(%rip), %rax
  mov %rax, 16(%rsp)
  mov recovery_stack(%rip), %rax
  mov %rax, 40(%rsp)
  movq $0x18, 24(%rsp)
  movq $0x10, 48(%rsp)
  pop %rax
  add $8, %rsp
  iretq

.section .note.GNU-stack,"",@progbits
