#include <linux/linkage.h>
#include <asm/assembler.h>
#include <asm/opcodes-virt.h>
#include <xen/interface/xen.h>

#ifndef HYPERVISOR_argo_op
#define __HYPERVISOR_argo_op               39
#endif

#define XEN_IMM 0xEA1

#define HYPERCALL_SIMPLE(hypercall)     \
ENTRY(HYPERVISOR_##hypercall)           \
    mov r12, #__HYPERVISOR_##hypercall; \
    __HVC(XEN_IMM);                     \
    ret lr;                 \
ENDPROC(HYPERVISOR_##hypercall)

#define HYPERCALL0 HYPERCALL_SIMPLE
#define HYPERCALL1 HYPERCALL_SIMPLE
#define HYPERCALL2 HYPERCALL_SIMPLE
#define HYPERCALL3 HYPERCALL_SIMPLE
#define HYPERCALL4 HYPERCALL_SIMPLE

#define HYPERCALL5(hypercall)           \
ENTRY(HYPERVISOR_##hypercall)           \
    stmdb sp!, {r4};                    \
    ldr r4, [sp, #4];                   \
    mov r12, #__HYPERVISOR_##hypercall; \
    __HVC(XEN_IMM);                     \
    ldm sp!, {r4};                      \
    ret lr;                 \
ENDPROC(HYPERVISOR_##hypercall)

HYPERCALL5(argo_op);
