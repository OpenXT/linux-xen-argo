#include <xen/page.h>
#include <xen/events.h>
#include <asm/xen/hypercall.h>
#include <xen/xen.h>

#ifndef HYPERVISOR_argo_op
#define __HYPERVISOR_argo_op	39

#ifndef _hypercall5
/*
 * Removed because unused in:
 * https://lkml.org/lkml/2018/8/20/267
 */
#define _hypercall5(type, name, a1, a2, a3, a4, a5)	\
({							\
	__HYPERCALL_DECLS;				\
	__HYPERCALL_5ARG(a1, a2, a3, a4, a5);		\
	asm volatile (__HYPERCALL			\
		: __HYPERCALL_5PARAM			\
		: __HYPERCALL_ENTRY(name)		\
		: __HYPERCALL_CLOBBER5);		\
	(type)__res;					\
})
#endif	/* _hypercall5*/

#if ( LINUX_VERSION_CODE < KERNEL_VERSION(5,2,0) )
#define __xen_stac() stac()
#define __xen_clac() clac()
#endif

static inline int __must_check
HYPERVISOR_argo_op(int cmd, void *arg1, void *arg2, uint32_t arg3,
	uint32_t arg4)
{
	int ret;

	__xen_stac();
	ret = _hypercall5(int, argo_op, cmd, arg1, arg2, arg3, arg4);
	__xen_clac();

	return ret;
}

#ifndef VIRQ_ARGO
#define VIRQ_ARGO   11 /* G. (DOM0) ARGO interdomain communication */
#endif

#endif /* _ARGO_H_ */
