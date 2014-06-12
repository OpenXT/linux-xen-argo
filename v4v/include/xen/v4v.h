/*
 * Copyright (c) 2013 Citrix Systems, Inc.
 * 
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 * 
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 * 
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 */

#ifndef __V4V_H__
#define __V4V_H__

/* Compiler specific hacks */
#if !defined(__GNUC__)
#define V4V_PACKED
#define V4V_INLINE __inline
#else /* __GNUC__ */
//
//#include  <xen/types.h>
#define V4V_PACKED __attribute__ ((packed))
#define V4V_INLINE inline
#endif /* __GNUC__ */

/* Get domid_t and DOMID_INVALID defined */
#ifdef __XEN__
#include <xen/types.h>
#include <public/xen.h>
typedef int ssize_t;            //FIXME this needs to be somewhere else
#define V4V_VOLATILE
#else
#if defined(__unix__)
#define V4V_VOLATILE volatile
/* If we're running on unix we can use the Xen headers */
#ifdef __KERNEL__
#include <xen/interface/xen.h>
#include <linux/version.h>
#else
typedef uint16_t domid_t; /* should be defined somewhere else */
#endif
#define V4V_VOLATILE volatile
/* why are they necessary ? Paulian
#include "xen.h"
#include <sys/types.h>
*/
#endif
#endif

#if !defined(__GNUC__)
#pragma pack(push, 1)
#pragma warning(push)
#pragma warning(disable: 4200)
#endif

#ifdef DEFINE_GUEST_HANDLE
# define DEFINE_XEN_GUEST_HANDLE DEFINE_GUEST_HANDLE
#endif

#define V4V_PROTO_DGRAM		0x3c2c1db8
#define V4V_PROTO_STREAM 	0x70f6a8e5

/************** Structure definitions **********/

#ifndef DOMID_INVALID
#define DOMID_INVALID (0x7FF4U)
#endif

#ifdef __i386__
#define V4V_RING_MAGIC  0xdf6977f231abd910ULL
#define V4V_PFN_LIST_MAGIC  0x91dd6159045b302dULL
#else
#define V4V_RING_MAGIC  0xdf6977f231abd910
#define V4V_PFN_LIST_MAGIC  0x91dd6159045b302d
#endif
#define V4V_DOMID_INVALID (0x7FFFU)
#define V4V_DOMID_NONE 	V4V_DOMID_INVALID
#define V4V_DOMID_ANY 	V4V_DOMID_INVALID
#define V4V_PORT_NONE   0

typedef struct v4v_iov
{
    uint64_t iov_base;
    uint64_t iov_len;
} V4V_PACKED v4v_iov_t;

#ifdef DEFINE_XEN_GUEST_HANDLE
DEFINE_XEN_GUEST_HANDLE (v4v_iov_t);
#endif

typedef struct v4v_addr
{
    uint32_t port;
    domid_t domain;
} V4V_PACKED v4v_addr_t;

#ifdef DEFINE_XEN_GUEST_HANDLE
DEFINE_XEN_GUEST_HANDLE (v4v_addr_t);
#endif

typedef struct v4v_viptables_rule
{
    struct v4v_addr src;
    struct v4v_addr dst;
    uint32_t accept;
} V4V_PACKED v4v_viptables_rule_t;

#ifdef DEFINE_XEN_GUEST_HANDLE
DEFINE_XEN_GUEST_HANDLE (v4v_viptables_rule_t);
#endif

typedef struct v4v_ring_id
{
    struct v4v_addr addr;
    domid_t partner;
} V4V_PACKED v4v_ring_id_t;

#define V4V_VIPTABLES_LIST_SIZE 8

typedef struct v4v_viptables_list
{
        struct v4v_viptables_rule rules[V4V_VIPTABLES_LIST_SIZE];
            uint32_t nb_rules;
} V4V_PACKED v4v_viptables_list_t;

#ifdef DEFINE_XEN_GUEST_HANDLE
DEFINE_XEN_GUEST_HANDLE (v4v_viptables_list_t);
#endif

typedef uint64_t v4v_pfn_t;
#ifdef DEFINE_XEN_GUEST_HANDLE
DEFINE_XEN_GUEST_HANDLE (v4v_pfn_t);
#endif

typedef struct v4v_pfn_list_t
{
    uint64_t magic;
    uint32_t npage;
    uint32_t pad;
    uint64_t reserved[3];
    v4v_pfn_t pages[0];
} V4V_PACKED v4v_pfn_list_t;

#ifdef DEFINE_XEN_GUEST_HANDLE
DEFINE_XEN_GUEST_HANDLE (v4v_pfn_list_t);
#endif


typedef struct v4v_ring
{
    uint64_t magic;
    struct v4v_ring_id id;      /*Identifies ring_id - xen only looks at this during register/unregister and will fill in id.addr.domain */
    uint32_t len;               /*length of ring[], must be a multiple of 8 */
    V4V_VOLATILE uint32_t rx_ptr; /*rx_ptr - modified by domain */
    V4V_VOLATILE uint32_t tx_ptr; /*tx_ptr - modified by xen */
    uint64_t reserved[4];
    V4V_VOLATILE uint8_t ring[0];
} V4V_PACKED v4v_ring_t;

#ifdef DEFINE_XEN_GUEST_HANDLE
DEFINE_XEN_GUEST_HANDLE (v4v_ring_t);
#endif

#ifdef __i386__
#define V4V_RING_DATA_MAGIC	0x4ce4d30fbc82e92aULL
#else
#define V4V_RING_DATA_MAGIC	0x4ce4d30fbc82e92a
#endif

#define V4V_RING_DATA_F_EMPTY       1U << 0 /*Ring is empty */
#define V4V_RING_DATA_F_EXISTS      1U << 1 /*Ring exists */
#define V4V_RING_DATA_F_PENDING     1U << 2 /*Pending interrupt exists - do not rely on this field - for profiling only */
#define V4V_RING_DATA_F_SUFFICIENT  1U << 3 /*Sufficient space to queue space_required bytes exists */

typedef struct v4v_ring_data_ent
{
    struct v4v_addr ring;
    uint16_t flags;
    uint32_t space_required;
    uint32_t max_message_size;
} V4V_PACKED v4v_ring_data_ent_t;

#ifdef DEFINE_XEN_GUEST_HANDLE
DEFINE_XEN_GUEST_HANDLE (v4v_ring_data_ent_t);
#endif

typedef struct v4v_ring_data
{
    uint64_t magic;
    uint32_t nent;
    uint32_t pad;
    uint64_t reserved[4];
    struct v4v_ring_data_ent data[0];
} V4V_PACKED v4v_ring_data_t;

#ifdef DEFINE_XEN_GUEST_HANDLE
DEFINE_XEN_GUEST_HANDLE (v4v_ring_data_t);
#endif


#define V4V_ROUNDUP(a) (((a) +0xf ) & ~0xf)
/* Messages on the ring are padded to 128 bits */
/* len here refers to the exact length of the data not including the 128 bit header*/
/* the the message uses ((len +0xf) & ~0xf) + sizeof(v4v_ring_message_header) bytes */


#define V4V_SHF_SYN		(1 << 0)
#define V4V_SHF_ACK		(1 << 1)
#define V4V_SHF_RST		(1 << 2)

#define V4V_SHF_PING		(1 << 8)
#define V4V_SHF_PONG		(1 << 9)

struct v4v_stream_header
{
    uint32_t flags;
    uint32_t conid;
} V4V_PACKED;

struct v4v_ring_message_header
{
    uint32_t len;
    struct v4v_addr source;
    uint16_t pad;
    uint32_t protocol;
    uint8_t data[0];

} V4V_PACKED;

/************************** Hyper calls ***************/

/*Prototype of hypercall is */
/*long do_v4v_op(int cmd,XEN_GUEST_HANDLE(void),XEN_GUEST_HANDLE(void),XEN_GUEST_HANDLE(void),uint32_t,uint32_t)*/


#define V4VOP_register_ring 	1
/*int, XEN_GUEST_HANDLE(v4v_ring_t) ring, XEN_GUEST_HANDLE(v4v_pfn_list_t) */

/* Registers a ring with Xen, if a ring with the same v4v_ring_id exists,
 * this ring takes its place, registration will not change tx_ptr 
 * unless it is invalid */

#define V4VOP_unregister_ring 	2
/*int, XEN_GUEST_HANDLE(v4v_ring_t) ring */

#define V4VOP_send 		3
/*int, XEN_GUEST_HANDLE(v4v_addr_t) src,XEN_GUEST_HANDLE(v4v_addr_t) dst,XEN_GUEST_HANDLE(void) buf, UINT32_t len,uint32_t protocol*/

/* Sends len bytes of buf to dst, giving src as the source address (xen will
 * ignore src->domain and put your domain in the actually message), xen
 * first looks for a ring with id.addr==dst and id.partner==sending_domain
 * if that fails it looks for id.addr==dst and id.partner==DOMID_ANY. 
 * protocol is the 32 bit protocol number used from the message
 * most likely V4V_PROTO_DGRAM or STREAM. If insufficient space exists
 * it will return -EAGAIN and xen will twing the V4V_INTERRUPT when
 * sufficient space becomes available */


#define V4VOP_notify 		4
/*int, XEN_GUEST_HANDLE(v4v_ring_data_t) buf*/

/* Asks xen for information about other rings in the system */
/* v4v_ring_data_t contains an array of v4v_ring_data_ent_t
 *
 * ent->ring is the v4v_addr_t of the ring you want information on
 * the same matching rules are used as for V4VOP_send.
 *
 * ent->space_required  if this field is not null xen will check
 * that there is space in the destination ring for this many bytes
 * of payload. If there is it will set the V4V_RING_DATA_F_SUFFICIENT
 * and CANCEL any pending interrupt for that ent->ring, if insufficient
 * space is available it will schedule an interrupt and the flag will
 * not be set.
 *
 * The flags are set by xen when notify replies
 * V4V_RING_DATA_F_EMPTY	ring is empty
 * V4V_RING_DATA_F_PENDING	interrupt is pending - don't rely on this
 * V4V_RING_DATA_F_SUFFICIENT	sufficient space for space_required is there
 * V4V_RING_DATA_F_EXISTS	ring exists
 */


#define V4VOP_sendv		5
/*int, XEN_GUEST_HANDLE(v4v_addr_t) src,XEN_GUEST_HANDLE(v4v_addr_t) dst,XEN_GUEST_HANDLE(v4v_iov_t) , UINT32_t niov,uint32_t protocol*/

/* Identical to V4VOP_send except rather than buf and len it takes 
 * an array of v4v_iov_t and a length of the array */

#define V4VOP_viptables_add     6
#define V4VOP_viptables_del     7
#define V4VOP_viptables_list    8

#if !defined(__GNUC__)
#pragma warning(pop)
#pragma pack(pop)
#endif

/************ Internal RING 0/-1 parts **********/
#if !defined(V4V_EXCLUDE_INTERNAL)

#if !defined(__GNUC__)
static __inline void
mb (void)
{
    _mm_mfence ();
    _ReadWriteBarrier ();
}
#endif

/*************** Utility functions **************/

static V4V_INLINE uint32_t
v4v_ring_bytes_to_read (volatile struct v4v_ring *r)
{
    int32_t ret;
    ret = r->tx_ptr - r->rx_ptr;
    if (ret >= 0)
        return ret;
    return (uint32_t) (r->len + ret);
}


/* Copy at most t bytes of the next message in the ring, into the buffer */
/* at _buf, setting from and protocol if they are not NULL, returns */
/* the actual length of the message, or -1 if there is nothing to read */


static ssize_t
v4v_copy_out (struct v4v_ring *r, struct v4v_addr *from, uint32_t * protocol,
              void *_buf, size_t t, int consume)
{
    volatile struct v4v_ring_message_header *mh;
    /* unnecessary cast from void * required by MSVC compiler */
    uint8_t *buf = (uint8_t *) _buf; 
    uint32_t btr = v4v_ring_bytes_to_read (r);
    uint32_t rxp = r->rx_ptr;
    uint32_t bte;
    uint32_t len;
    ssize_t ret;


    if (btr < sizeof (*mh))
        return -1;

/*Becuase the message_header is 128 bits long and the ring is 128 bit aligned, we're gaurunteed never to wrap*/
    mh = (volatile struct v4v_ring_message_header *) &r->ring[r->rx_ptr];

    len = mh->len;
    if (btr < len)
        return -1;

#if defined(__GNUC__) 
    if (from)
        *from = mh->source;
#else
	/* MSVC can't do the above */
    if (from)
	memcpy((void *) from, (void *) &(mh->source), sizeof(struct v4v_addr));
#endif

    if (protocol)
        *protocol = mh->protocol;

    rxp += sizeof (*mh);
    if (rxp == r->len)
        rxp = 0;
    len -= sizeof (*mh);
    ret = len;

    bte = r->len - rxp;

    if (bte < len)
      {
          if (t < bte)
            {
                if (buf)
                  {
                      memcpy (buf, (void *) &r->ring[rxp], t);
                      buf += t;
                  }

                rxp = 0;
                len -= bte;
                t = 0;
            }
          else
            {
                if (buf)
                  {
                      memcpy (buf, (void *) &r->ring[rxp], bte);
                      buf += bte;
                  }
                rxp = 0;
                len -= bte;
                t -= bte;
            }
      }

    if (buf && t)
        memcpy (buf, (void *) &r->ring[rxp], (t < len) ? t : len);


    rxp += V4V_ROUNDUP (len);
    if (rxp == r->len)
        rxp = 0;

    mb ();

    if (consume)
        r->rx_ptr = rxp;


    return ret;
}

#endif /* V4V_EXCLUDE_INTERNAL */

#endif /* __V4V_H__ */

/*
 * Local variables:
 * mode: C
 * c-set-style: "BSD"
 * c-basic-offset: 4
 * tab-width: 4
 * indent-tabs-mode: nil
 * End:
 */
