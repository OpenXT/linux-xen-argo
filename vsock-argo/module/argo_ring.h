#ifndef _ARGO_RING_H_
# define _ARGO_RING_H_

#include <linux/skbuff.h>

#include <xen/argo.h>

/*
 * Ring GFN management.
 */
struct argo_gfn_array {
	size_t n;
	xen_argo_gfn_t gfns[0];
};

/*
 * xen_argo_ring_t does not have a length field.
 * Arbitrary fixed ring size for now.
 * This size is chosen to match other Argo driver implementations.
 */
static const size_t ring_len = 32 * PAGE_SIZE;

/*
 * Messages on the ring are aligned on XEN_ARGO_MSG_SLOT_SIZE.
 * XEN_ARGO_MSG_SLOT_SIZE needs to be a power of 2.
 */
#define ARGO_RING_ALIGN(a) round_up((a), XEN_ARGO_MSG_SLOT_SIZE)

static inline void argo_ring_check_sizes(void)
{
	BUILD_BUG_ON_NOT_POWER_OF_2(XEN_ARGO_MSG_SLOT_SIZE);
}

/*
 * Ring management.
 */
typedef int (*argo_recv_skb_cb)(void *priv, struct sk_buff *skb);
struct argo_ring_hnd {
	struct list_head l;
	spinlock_t ring_lock;
	xen_argo_ring_t *ring;
	unsigned int ring_len;
	struct argo_gfn_array *gfns;
	xen_argo_port_t aport;
	domid_t partner_id;
	argo_recv_skb_cb recv_cb;
	void *priv;	/* TODO: Do better. Opaque to get struct
			   vsock_sock/struct sock to recv_cb */
};

/*
 * Ring handle primitives.
 */
void argo_ring_handle_free(struct argo_ring_hnd *h);
struct argo_ring_hnd *argo_ring_handle_alloc(domid_t domain, unsigned int port,
		argo_recv_skb_cb recv_cb, void *priv);

/*
 * Ring primitives, hypercalls to Xen.
 */
void argo_ring_unregister(struct argo_ring_hnd *h);
int argo_ring_register(struct argo_ring_hnd *h);

/*
 * Ring "send" primitive. send is synchronous, direct hypercall to Xen.
 */
int argo_ring_send_skb(struct argo_ring_hnd *h, const struct sk_buff *skb,
		xen_argo_send_addr_t *send);

int argo_core_init(void);
void argo_core_cleanup(void);

#endif /* !_ARGO_RING_H_ */
