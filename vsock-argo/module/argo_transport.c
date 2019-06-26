#include <linux/types.h>
#include <linux/string.h>
#include <linux/kmod.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/net.h>
#include <linux/netdevice.h>
#include <linux/random.h>

#include <net/sock.h>
#include <net/af_vsock.h>
#include <net/vsock_addr.h>

#include "argo_ring.h"

/*
 * Argo auto-bind default address.
 */
static const struct sockaddr_vm addr_auto = {
	.svm_family = AF_VSOCK,
	.svm_cid = XEN_ARGO_DOMID_ANY,
	.svm_port = 0,
	.svm_zero = { 0 },
};

/*
 * Argo private data.
 */
struct argo_transport {
	struct list_head sockets;	/* List of all argo_transport. */
	struct argo_ring_hnd *h;	/* Argo ring handle. */
	struct vsock_sock *vsk;		/* Parent vsock struct. */
};

/*
 * Global socket list.
 */
struct list_head sockets = LIST_HEAD_INIT(sockets);

/*
 * Private data helpers.
 */
#define argo_trans(vsk)	((struct argo_transport *)((vsk)->trans))

/*
 * Initialize/Tear-down socket.
 */
static int argo_transport_socket_init(
	struct vsock_sock *vsk, struct vsock_sock *psk)
{
	vsk->trans = kmalloc(sizeof (struct argo_transport), GFP_KERNEL);
	if (!vsk->trans)
		return -ENOMEM;
	INIT_LIST_HEAD(&argo_trans(vsk)->sockets);
	list_add_tail(&argo_trans(vsk)->sockets, &sockets);
	argo_trans(vsk)->vsk = vsk;
	argo_trans(vsk)->h = NULL;

	return 0;
}

static void argo_transport_destruct(struct vsock_sock *vsk)
{
	argo_trans(vsk)->vsk = NULL;
	list_del_init(&argo_trans(vsk)->sockets);
	kfree(argo_trans(vsk));
	vsk->trans = NULL;

	return;
}

static void argo_transport_release(struct vsock_sock *vsk)
{
	struct argo_transport *t = argo_trans(vsk);

	vsock_remove_sock(vsk);

	/*
	 * Disconnect/Detach before release of resources:
	 * TODO: Send RST for STREAM.
	 */

	if (t->h) {
		argo_ring_unregister(t->h);
		argo_ring_handle_free(t->h);
	}
}

/*
 * VSock VMADDR_CID_ANY & VMADDR_PORT_ANY do not match Argo definitions.
 * Convert sockaddr_vm to sockaddr_vm argo compatible:
 * - CID: 0 -> XEN_ARGO_DOMID_ANY.
 * - PORT: 0 -> ~0U - 1 ?
 */
static inline int sockaddr_vm_normalize(struct sockaddr_vm *addr)
{
	if (addr->svm_cid == VMADDR_CID_ANY)
		addr->svm_cid = addr_auto.svm_cid;
	if (addr->svm_port == VMADDR_PORT_ANY)
		addr->svm_port = addr_auto.svm_port;

	if (addr->svm_cid > XEN_ARGO_DOMID_ANY)
		return EINVAL;

	return 0;
}
static inline int sockaddrvm_to_argo(const struct sockaddr_vm *s, xen_argo_addr_t *d)
{
	struct sockaddr_vm c = *s;

	if (sockaddr_vm_normalize(&c))
		return EINVAL;

	d->domain_id = s->svm_cid;
	d->aport = s->svm_port;
	d->pad = 0;

	return 0;
}

static inline bool sockaddr_vm_match(const struct sockaddr_vm *src,
	const struct sockaddr_vm *dst)
{
	return ((src->svm_cid == dst->svm_cid) &&
		(src->svm_port == dst->svm_port));
}

/*
 * Connections.
 */
static int argo_transport_connect(struct vsock_sock *vsk)
{
	if (!vsock_addr_bound(&vsk->local_addr))
		return -EINVAL;
	if (!vsock_addr_bound(&vsk->remote_addr))
		return -EINVAL;

	/* TODO: STREAM will require SYN/ACK dance here.
	 *	 DGRAM requires nothing right? */

	return -ECONNREFUSED;
}

/*
 * DGRAM.
 */
static int argo_transport_recv_dgram_cb(void *priv, struct sk_buff *skb);
static int argo_transport_dgram_bind(struct vsock_sock *vsk,
	struct sockaddr_vm *addr)
{
	struct argo_transport *t = argo_trans(vsk);
	int rc;

	if (sockaddr_vm_normalize(addr))
		return EINVAL;

	/* Auto-bind local_addr. */
	memcpy(&vsk->local_addr, addr, sizeof (*addr));

	t->h = argo_ring_handle_alloc(addr->svm_cid, addr->svm_port,
		argo_transport_recv_dgram_cb, vsk);
	if (IS_ERR(t->h)) {
		rc = PTR_ERR(t->h);
		pr_debug("argo_ring_handle_alloc(dom%u:%u) %s (%d).\n",
			addr->svm_cid, addr->svm_port,
			rc ? "failed" : "succeed", -rc);
		goto failed_alloc;
	}

	rc = argo_ring_register(t->h);
	if (rc) {
		pr_debug("argo_ring_register(dom%u:%u) %s (%d).\n",
			addr->svm_cid, addr->svm_port,
			rc ? "failed" : "succeed", -rc);
		goto failed_register;
	}

	return 0;

failed_register:
	argo_ring_handle_free(t->h);
	t->h = NULL;
failed_alloc:
	return rc;
}

static int argo_transport_dgram_enqueue(struct vsock_sock *vsk,
	struct sockaddr_vm *remote_addr, struct msghdr *msg, size_t len)
{
	int rc = 0;
	struct sk_buff *skb;
	xen_argo_send_addr_t sendaddr;

	/* TODO: Auto-bind already done? */
	if (sockaddrvm_to_argo(&vsk->local_addr, &sendaddr.src) ||
		sockaddrvm_to_argo(remote_addr, &sendaddr.dst))
		return EINVAL;

	skb = alloc_skb(len, GFP_ATOMIC);
	if (!skb) {
		pr_debug("%s: alloc_skb failed.\n", __func__);
		return -ENOMEM;
	}

	if (memcpy_from_msg(skb_put(skb, len), msg, len)) {
		pr_debug("%s: memcpy_from_msg failed.\n", __func__);
		rc = -EMSGSIZE;
		goto out;
	}

	rc = argo_ring_send_skb(argo_trans(vsk)->h, skb, &sendaddr);
	if (rc < 0) {
		pr_debug("%s: argo_ring_send_skb failed.\n", __func__);
		goto out;
	}

	pr_debug("enqueued %zuB dom%u:%u to dom%u:%u.\n", len,
		sendaddr.src.domain_id, sendaddr.src.aport,
		sendaddr.dst.domain_id, sendaddr.dst.aport);

out:
	kfree_skb(skb);
	return rc;
}

static int argo_transport_recv_dgram_cb(void *priv, struct sk_buff *skb)
{
	struct vsock_sock *vsk = priv;
	struct sock *sk = &vsk->sk;
	int rc;

	/* sk_receive_skb() does sock_put(). */
	sock_hold(sk);
	rc = sk_receive_skb(sk, skb, 0);
	if (rc != NET_RX_SUCCESS)
		pr_warn("dom%u:%u cannot queue packet, dropping.",
			vsk->local_addr.svm_cid,
			vsk->local_addr.svm_port);
	return rc == NET_RX_SUCCESS ? 0 : -1;
}

static int argo_transport_dgram_dequeue(struct vsock_sock *vsk,
	struct msghdr *msg, size_t len, int flags)
{
	struct sk_buff *skb;
	struct xen_argo_ring_message_header *mh;
	size_t msg_len;
	int rc = 0;

	skb = skb_recv_datagram(&vsk->sk, flags, flags & MSG_DONTWAIT, &rc);
	if (!skb) {
		pr_debug("skb_recv_datagram failed (%d).\n", rc);
		goto out;
	}

	/* Assume skb is always in linear data area for now. */
	mh = (void*)skb->data;
	if (!mh) {
		pr_debug("could not access sk_buff data to read message header, dropping packet.\n");
		goto out;
	}

	msg_len = mh->len - sizeof (*mh);
	rc = skb_copy_datagram_msg(skb, sizeof (*mh), msg, msg_len);
	if (rc)
		goto out;

	if (msg->msg_name) {
		DECLARE_SOCKADDR(struct sockaddr_vm *, vm_addr, msg->msg_name);
		vsock_addr_init(vm_addr, mh->source.domain_id, mh->source.aport);
		msg->msg_namelen = sizeof (*vm_addr);
		pr_debug("dequeued: report source as dom%u:%u\n",
			vm_addr->svm_cid, vm_addr->svm_port);
	}
	pr_debug("dequeued skb: %uB (%zuB data) from dom%u:%u\n",
		mh->len, msg_len, mh->source.domain_id, mh->source.aport);

	rc = msg_len;
out:
	skb_free_datagram(&vsk->sk, skb);
	return rc;
}

static bool argo_transport_dgram_allow(u32 cid, u32 port)
{
	return true;
}


/*
 * TODO: STREAM.
 */
#ifdef TODO_STREAM
static ssize_t argo_transport_stream_dequeue(
	struct vsock_sock *vsk,
	struct msghdr *msg,
	size_t len,
	int flags)
{
	return -ENOTSUP;
}

static ssize_t argo_transport_stream_enqueue(
	struct vsock_sock *vsk,
	struct msghdr *msg,
	size_t len)
{
	return -ENOTSUP;
}

static s64 argo_transport_stream_has_data(struct vsock_sock *vsk)
{
	return -ENOTSUP;
}

static s64 argo_transport_stream_has_space(struct vsock_sock *vsk)
{
	return -ENOTSUP;
}

static u64 argo_transport_stream_rcvhiwat(struct vsock_sock *vsk)
{
	return -ENOTSUP;
	/* TODO: Return high-watermark... probably something to frob around
	   with. */
}

static bool argo_transport_stream_is_active(struct vsock_sock *vsk)
{
	return false;
}

static bool argo_transport_stream_allow(u32 cid, u32 port)
{
	/* TODO: Pre-filtering can be done in here. */
	return false;
}
#endif /* TODO_STREAM */

/*
 * Notification.
 */
static int argo_transport_notify_poll_in(
	struct vsock_sock *vsk,
	size_t target,
	bool *data_ready_now)
{
	*data_ready_now = vsock_stream_has_data(vsk);
	return 0;
}

static int argo_transport_notify_poll_out(
	struct vsock_sock *vsk,
	size_t target,
	bool *space_available_now)
{
	*space_available_now = vsock_stream_has_space(vsk);
	return 0;
}

static int argo_transport_notify_recv_init(
	struct vsock_sock *vsk,
	size_t target,
	struct vsock_transport_recv_notify_data *data)
{
	/* TODO: Not sure... */
	return 0;
}

static int argo_transport_notify_recv_pre_block(
	struct vsock_sock *vsk,
	size_t target,
	struct vsock_transport_recv_notify_data *data)
{
	/* TODO: Not sure... */
	return 0;
}

static int argo_transport_notify_recv_pre_dequeue(
	struct vsock_sock *vsk,
	size_t target,
	struct vsock_transport_recv_notify_data *data)
{
	/* TODO: Not sure... */
	return 0;
}

static int argo_transport_notify_recv_post_dequeue(
	struct vsock_sock *vsk,
	size_t target,
	ssize_t copied,
	bool data_read,
	struct vsock_transport_recv_notify_data *data)
{
	/* TODO: Not sure... */
	return 0;
}

static int argo_transport_notify_send_init(
	struct vsock_sock *vsk,
	struct vsock_transport_send_notify_data *data)
{
	/* TODO: Not sure... */
	return 0;
}

static int argo_transport_notify_send_pre_block(
	struct vsock_sock *vsk,
	struct vsock_transport_send_notify_data *data)
{
	/* TODO: Not sure... */
	return 0;
}

static int argo_transport_notify_send_pre_enqueue(
	struct vsock_sock *vsk,
	struct vsock_transport_send_notify_data *data)
{
	/* TODO: Not sure... */
	return 0;
}

static int argo_transport_notify_send_post_enqueue(
	struct vsock_sock *vsk,
	ssize_t written,
	struct vsock_transport_send_notify_data *data)
{
	/* TODO: Not sure... */
	return 0;
}

/*
 * Shutdown.
 */
static int argo_transport_shutdown(struct vsock_sock *vsk, int mode)
{
	/* TODO: That might be where we want to send RST instead... */
	return 0;
}

/*
 * Buffer sizes.
 */
static void argo_transport_set_buffer_size(struct vsock_sock *vsk, u64 val)
{
	/* TODO: Probably not usable in our case. */
}

static void argo_transport_set_min_buffer_size(struct vsock_sock *vsk, u64 val)
{
}

static void argo_transport_set_max_buffer_size(struct vsock_sock *vsk, u64 val)
{
}

static u64 argo_transport_get_buffer_size(struct vsock_sock *vsk)
{
	return 0ULL;
}

static u64 argo_transport_get_min_buffer_size(struct vsock_sock *vsk)
{
	return 0ULL;
}

static u64 argo_transport_get_max_buffer_size(struct vsock_sock *vsk)
{
	return 0ULL;
}

static u32 argo_transport_get_local_cid(void)
{
	/* TODO: May require svm_cid format instead of Argo. */
	return XEN_ARGO_DOMID_ANY;
}

static struct vsock_transport argo_transport = {
	.init = argo_transport_socket_init,
	.destruct = argo_transport_destruct,
	.release = argo_transport_release,

	.connect = argo_transport_connect,

	.dgram_bind = argo_transport_dgram_bind,
	.dgram_dequeue = argo_transport_dgram_dequeue,
	.dgram_enqueue = argo_transport_dgram_enqueue,
	.dgram_allow = argo_transport_dgram_allow,

#ifdef TODO_STREAM
	.stream_dequeue = argo_transport_stream_dequeue,
	.stream_enqueue = argo_transport_stream_enqueue,
	.stream_has_data = argo_transport_stream_has_data,
	.stream_has_space = argo_transport_stream_has_space,
	.stream_rcvhiwat = argo_transport_stream_rcvhiwat,
	.stream_is_active = argo_transport_stream_is_active,
	.stream_allow = argo_transport_stream_allow,
#endif /* TODO_STREAM */
	.notify_poll_in = argo_transport_notify_poll_in,
	.notify_poll_out = argo_transport_notify_poll_out,
	.notify_recv_init = argo_transport_notify_recv_init,
	.notify_recv_pre_block = argo_transport_notify_recv_pre_block,
	.notify_recv_pre_dequeue = argo_transport_notify_recv_pre_dequeue,
	.notify_recv_post_dequeue = argo_transport_notify_recv_post_dequeue,
	.notify_send_init = argo_transport_notify_send_init,
	.notify_send_pre_block = argo_transport_notify_send_pre_block,
	.notify_send_pre_enqueue = argo_transport_notify_send_pre_enqueue,
	.notify_send_post_enqueue = argo_transport_notify_send_post_enqueue,

	.shutdown = argo_transport_shutdown,

	.set_buffer_size = argo_transport_set_buffer_size,
	.set_min_buffer_size = argo_transport_set_min_buffer_size,
	.set_max_buffer_size = argo_transport_set_max_buffer_size,
	.get_buffer_size = argo_transport_get_buffer_size,
	.get_min_buffer_size = argo_transport_get_min_buffer_size,
	.get_max_buffer_size = argo_transport_get_max_buffer_size,

	.get_local_cid = argo_transport_get_local_cid,
};

static int __init argo_transport_init(void)
{
	int rc;

	rc = vsock_core_init(&argo_transport);
	if (rc) {
		pr_err("vsock_core_init() failed (%d).\n", rc);
		return rc;
	}
	rc = argo_core_init();
	if (rc) {
		pr_err("argo_core_init() failed (%d).\n", rc);
		vsock_core_exit();
		return rc;
	}
	pr_info("vsock_argo_transport registered.\n");

	return 0;
}
module_init(argo_transport_init);

static void __exit argo_transport_exit(void)
{
	/* TODO: Flush sockets... */

	pr_info("vsock_argo_transport unregistered.\n");
	argo_core_cleanup();
	vsock_core_exit();
	return;
}
module_exit(argo_transport_exit);

MODULE_AUTHOR("Assured Information Security, Inc.");
MODULE_DESCRIPTION("Argo transport for Virtual Socket.");
MODULE_VERSION("1.0.0");
MODULE_LICENSE("GPL");
MODULE_ALIAS("argo_vsock");
MODULE_ALIAS_NETPROTO(argo_vsock);
