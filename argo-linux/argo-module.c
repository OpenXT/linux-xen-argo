/******************************************************************************
 * drivers/xen/argo/argo.c
 *
 * Argo: Hypervisor-Mediated data eXchange
 *
 * Derived from v4v, the version 2 of v2v.
 *
 * Copyright (c) 2009 Ross Philipson
 * Copyright (c) 2009 James McKenzie
 * Copyright (c) 2009 Citrix Systems, Inc.
 * Modifications by Christopher Clark are Copyright (c) 2018 BAE Systems
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License version 2
 * as published by the Free Software Foundation; or, when distributed
 * separately from the Linux kernel or incorporated into other
 * software packages, subject to the following license:
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this source file (the "Software"), to deal in the Software without
 * restriction, including without limitation the rights to use, copy, modify,
 * merge, publish, distribute, sublicense, and/or sell copies of the Software,
 * and to permit persons to whom the Software is furnished to do so, subject to
 * the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
 * FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS
 * IN THE SOFTWARE.
 */

#include <linux/version.h>

#ifndef CONFIG_PARAVIRT
#define CONFIG_PARAVIRT
#endif

#ifdef XC_DKMS
#include "xen-dkms.h"
#else /* ! XC_DKMS */
#define xc_bind_virq_to_irqhandler bind_virq_to_irqhandler
#define xc_unbind_from_irqhandler unbind_from_irqhandler
#endif /* XC_DKMS */

#include <linux/version.h>
#include <linux/compat.h>
#include <linux/mm.h>
#include <linux/init.h>
#include <linux/module.h>
#include <linux/vmalloc.h>
#include <linux/interrupt.h>
#include <linux/spinlock.h>
#include <linux/list.h>
#include <linux/socket.h>

#ifdef XC_KERNEL
#include <asm/hypercall.h>
#include <xen/hypercall.h>
#else /* ! XC_KERNEL */
#ifdef XC_DKMS
#include <xen/xen.h>
#endif /* XC_DKMS */
#include <linux/sched.h>
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,11,0)
#include <linux/cred.h>
#include <linux/sched/signal.h>
#endif
#endif /* XC_KERNEL */

#include "argo.h"
#include <xen/evtchn.h>
#include <xen/argo.h>
#include <linux/argo_dev.h>
#include <linux/fs.h>
#include <linux/platform_device.h>
#include <linux/miscdevice.h>
#include <linux/major.h>
#include <linux/proc_fs.h>
#include <linux/poll.h>
#include <linux/random.h>
#include <linux/wait.h>
#include <linux/file.h>
#include <linux/mount.h>
#include <linux/dcache.h>
#include <linux/slab.h>
#if ( LINUX_VERSION_CODE >= KERNEL_VERSION(5,3,0) )
#include <linux/pseudo_fs.h>
#endif

#if ( LINUX_VERSION_CODE >= KERNEL_VERSION(5,0,0) )
# define access_ok_wrapper(type, addr, size) access_ok((addr), (size))
#else
# define access_ok_wrapper(type, addr, size) access_ok((type), (addr), (size))
#endif

#define XEN_ARGO_ROUNDUP(x) roundup((x), XEN_ARGO_MSG_SLOT_SIZE)

#define MOAN do { printk(KERN_ERR "%s:%d MOAN called\n",__FILE__,__LINE__); } while (1==0)

#define DEFAULT_RING_SIZE     (XEN_ARGO_ROUNDUP((((PAGE_SIZE)*32) - sizeof(xen_argo_ring_t)-XEN_ARGO_ROUNDUP(1))))

#define DEBUG_ORANGE(a) do { printk(KERN_ERR  "%s %s %s:%d cpu%d pid %d\n",a,__PRETTY_FUNCTION__,"argo.c",__LINE__,raw_smp_processor_id(),current->pid); } while (1==0)

/*#define ARGO_DEBUG 1*/
#undef ARGO_DEBUG
#undef ARGO_DEBUG_LOCKS

#ifdef ARGO_DEBUG

#define DEBUG_BANANA DEBUG_ORANGE("BANANA")
#define DEBUG_APPLE DEBUG_ORANGE("")
#define lock2(a,b) do { printk(KERN_ERR  "%s(%s) %s %s:%d cpu%d\n",#a,#b, __PRETTY_FUNCTION__,"argo.c",__LINE__,raw_smp_processor_id()); a(b); } while (1==0)
#define lock3(a,b,c) do { printk(KERN_ERR  "%s(%s,%s) %s %s:%d cpu%d\n",#a,#b,#c, __PRETTY_FUNCTION__,"argo.c",__LINE__,raw_smp_processor_id()); a(b,c); } while (1==0)
#define DEBUG_RING(a) summary_ring(a)
#define DEBUG_HEXDUMP(a,b) argo_hexdump(a,b)

#else /* ! ARGO_DEBUG */

#define DEBUG_BANANA (void)0
#define DEBUG_APPLE (void)0
#define lock2(a,b) a(b)
#define lock3(a,b,c) a(b,c)
#define DEBUG_RING(a) (void)0
#define DEBUG_HEXDUMP(a,b) (void)0

#endif /* ARGO_DEBUG */

#define argo_read_lock(a) lock2(read_lock,a)
#define argo_read_unlock(a) lock2(read_unlock,a)
#define argo_write_lock(a) lock2(write_lock,a)
#define argo_write_unlock(a) lock2(write_unlock,a)
#define argo_write_lock_irqsave(a,b)  lock3(write_lock_irqsave,a,b)
#define argo_write_unlock_irqrestore(a,b)  lock3(write_unlock_irqrestore,a,b)

#ifndef ARGO_DEBUG_LOCKS
#define argo_spin_lock_init(a) lock2(spin_lock_init,a)
#define argo_spin_lock(a) lock2(spin_lock,a)
#define argo_spin_unlock(a) lock2(spin_unlock,a)
#define argo_spin_lock_irqsave(a,b)  lock3(spin_lock_irqsave,a,b)
#define argo_spin_unlock_irqrestore(a,b)  lock3(spin_unlock_irqrestore,a,b)
#define argo_spinlock_t spinlock_t
#else /* ARGO_DEBUG_LOCKS */


typedef struct
{
    atomic_t lock;
    int line;
} argo_spinlock_t;


static void
do_spin_lock_init(argo_spinlock_t * l)
{
    atomic_set(&l->lock, 0);
    l->line = -1;
}

static void
do_spin_lock(argo_spinlock_t * l, int line)
{
    int i;

    while (1)
    {
        for (i = 0; i < 1000000; ++i)
        {
            int got_lock = atomic_add_unless (&l->lock, 1, 1);
            if (got_lock)
            {
                l->line = line;
                return;
            }
        }

        printk(KERN_ERR
               "argo_spin_lock at line %d is blocking on lock acquired at line %d\n",
               line, l->line);
    }
}

static void
do_spin_unlock(argo_spinlock_t * l, int line)
{
    if ( atomic_read (&l->lock) != 1 )
    {
        printk(KERN_ERR "argo_spin_unlock at line %d called while lock=%d\n",
               line, atomic_read (&l->lock));
        atomic_set (&l->lock, 0);
        return;
    }
    atomic_dec (&l->lock);
}

#define do_spin_lock_irqsave(a,b,c) do { local_irq_save(b); do_spin_lock(a,c); } while (1==0)
#define do_spin_unlock_irqrestore(a,b,c) do { do_spin_unlock(a,c); local_irq_restore(b); } while (1==0)

#define argo_spin_lock_init(a) do_spin_lock_init(a)
#define argo_spin_lock(a) do_spin_lock(a,__LINE__)
#define argo_spin_unlock(a) do_spin_unlock(a,__LINE__)
#define argo_spin_lock_irqsave(a,b)  do_spin_lock_irqsave(a,b,__LINE__)
#define argo_spin_unlock_irqrestore(a,b)  do_spin_unlock_irqrestore(a,b,__LINE__)
#endif /* ! ARGO_DEBUG_LOCKS */


/*The type of a ring*/
typedef enum
{
  ARGO_RTYPE_IDLE = 0,
  ARGO_RTYPE_DGRAM,
  ARGO_RTYPE_LISTENER,
  ARGO_RTYPE_CONNECTOR,
} argo_rtype;


/*the state of an argo_private*/
typedef enum
{
  ARGO_STATE_IDLE = 0,
  ARGO_STATE_BOUND,              /*this can only be held by the ring sponsor */
  ARGO_STATE_LISTENING,          /*this can only be held by the ring sponsor */
  ARGO_STATE_ACCEPTED,
  ARGO_STATE_CONNECTING,         /*this can only be held by the ring sponsor */
  ARGO_STATE_CONNECTED,          /*this can only be held by the ring sponsor */
  ARGO_STATE_DISCONNECTED
} argo_state;


static rwlock_t list_lock;
static struct list_head ring_list;

/*----------------- message formatting ---------------------*/
/* FIXME: does this belong here? */

#define ARGO_SHF_SYN     (1 << 0)
#define ARGO_SHF_ACK     (1 << 1)
#define ARGO_SHF_RST     (1 << 2)

#define ARGO_SHF_PING        (1 << 8)
#define ARGO_SHF_PONG        (1 << 9)

#define ARGO_PROTO_DGRAM     0x6447724d
#define ARGO_PROTO_STREAM    0x3574526d

struct argo_stream_header
{
    uint32_t flags;
    uint32_t conid;
};

static uint32_t
argo_ring_bytes_to_read(volatile struct xen_argo_ring *r, uint32_t ring_size)
{
    int32_t ret;
    ret = r->tx_ptr - r->rx_ptr;
    if ( ret >= 0 )
        return ret;
    return (uint32_t) (ring_size + ret);
}

/*
 * argo_copy_out :
 * Copy at most t bytes of the next message in the ring, into the buffer
 * at _buf, setting from and protocol if they are not NULL.
 * Returns actual length of the message or -1 if there is nothing to read.
 */
static ssize_t
argo_copy_out(struct xen_argo_ring *r, uint32_t ring_size,
              struct xen_argo_addr *from, uint32_t * protocol,
              void *_buf, size_t t, int consume)
{
    volatile struct xen_argo_ring_message_header *mh;
    /* unnecessary cast from void * required by MSVC compiler */
    uint8_t *buf = (uint8_t *) _buf;
    uint32_t btr = argo_ring_bytes_to_read(r, ring_size);
    uint32_t rxp = r->rx_ptr;
    uint32_t bte;
    uint32_t len;
    ssize_t ret;

    if ( btr < sizeof (*mh) )
        return -1;

    /*
     * Since the message_header is 128 bits long and the ring is
     * 128 bit aligned, we are guaranteed never to wrap.
     */
    mh = (volatile struct xen_argo_ring_message_header *) &r->ring[r->rx_ptr];

    len = mh->len;
    if ( btr < len )
        return -1;

#if defined(__GNUC__)
    if ( from )
        *from = mh->source;
#else
    /* MSVC can't do the above */
    if ( from )
        memcpy((void *) from, (void *) &(mh->source),
               sizeof(struct xen_argo_addr));
#endif

    if ( protocol )
        *protocol = mh->message_type;

    rxp += sizeof(*mh);
    if ( rxp == ring_size )
        rxp = 0;
    len -= sizeof(*mh);
    ret = len;

    bte = ring_size - rxp;

    if ( bte < len )
    {
        if ( t < bte )
        {
            if ( buf )
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
            if ( buf )
            {
                memcpy(buf, (void *) &r->ring[rxp], bte);
                buf += bte;
            }
            rxp = 0;
            len -= bte;
            t -= bte;
        }
    }
    if ( buf && t )
        memcpy(buf, (void *) &r->ring[rxp], (t < len) ? t : len);

    rxp += XEN_ARGO_ROUNDUP(len);
    if ( rxp == ring_size )
        rxp = 0;

    mb();

    if ( consume )
        r->rx_ptr = rxp;

    return ret;
}

/*-----------------                    ---------------------*/

struct argo_private;

/* Ring pointer itself is protected by the refcnt, the lists its in by list_lock.
 * It's permittable to decrement the refcnt whilst holding the read lock,
 * and then clean up refcnt=0 rings later.
 * If a ring has (refcnt != 0) we expect ->ring to be non NULL, and for the ring to 
 * be registered with Xen.
 */

struct ring
{
    struct list_head node;
    atomic_t refcnt;

    /*Protects the data in the xen_argo_ring_t also privates and sponsor */
    argo_spinlock_t lock;

    struct list_head privates;     /* Protected by lock */
    struct argo_private *sponsor;  /* Protected by lock */

    argo_rtype type;

    /*Ring */
    xen_argo_ring_t *ring;
    struct argo_ring_id id;
    uint32_t len;
    xen_argo_gfn_t *gfn_array;
    int npfns;
    int order;
};

struct argo_private
{
    struct list_head node;
    argo_state state;
    argo_ptype ptype;

    uint32_t desired_ring_size;
    struct ring *r;

    wait_queue_head_t readq;
    wait_queue_head_t writeq;

    xen_argo_addr_t peer;
    uint32_t conid;

    /* Protects pending messages, and pending_error */
    argo_spinlock_t pending_recv_lock;

    struct list_head pending_recv_list; /*For LISTENER contains only ... */
    atomic_t pending_recv_count;
    int pending_error;
    int full;

    int send_blocked;
    int rx;

    struct timer_list to;
};

struct pending_recv
{
    struct list_head node;
    xen_argo_addr_t from;
    size_t data_len, data_ptr;
    struct argo_stream_header sh;
    uint8_t data[0];
} ARGO_PACKED;


static argo_spinlock_t interrupt_lock;
static argo_spinlock_t pending_xmit_lock;
static struct list_head pending_xmit_list;
static atomic_t pending_xmit_count;

enum argo_pending_xmit_type
{
    /*Send the inline xmit */
    ARGO_PENDING_XMIT_INLINE = 1,

    /*Wake up writeq of sponsor of the ringid from */
    ARGO_PENDING_XMIT_WAITQ_MATCH_SPONSOR,

    /*Wake up writeq of a private of ringid from with conid conid */
    ARGO_PENDING_XMIT_WAITQ_MATCH_PRIVATES,
};

struct pending_xmit
{
    struct list_head node;
    enum argo_pending_xmit_type type;
    uint32_t conid;
    struct argo_ring_id from;
    xen_argo_addr_t to;
    size_t len;
    uint32_t protocol;
    uint8_t data[0];
};

#define MAX_PENDING_RECVS   2

/************************debugging **********************************/


#define MAGIC 0x12345678

//#ifdef ARGO_DEBUG
#if 0
#define argo_kfree(a) do_argo_kfree(a,__LINE__)
#define argo_kmalloc(a,b) do_argo_kmalloc(a,b,__LINE__)
static int total = 0, big_total = 1024 * 1024;

#define N_LINES 16384
static int lines[N_LINES];

#define N_MALLOC 65536

static int malloc_line[N_MALLOC];
static void *malloc_ptr[N_MALLOC];

static void
malloc_profile (void)
{
  int i;
  memset (lines, 0, sizeof(lines));
  for (i = 0; i < N_MALLOC; ++i)
    {
      if (malloc_ptr[i])
        lines[malloc_line[i]]++;
    }

  for (i = 0; i < N_LINES; ++i)
    {
      if (lines[i])
        printk ("malloc_debug: line %5d: %d mallocs\n", i, lines[i]);
    }
}

static void
do_argo_kfree (void *_a, int line)
{
  uint8_t *a = _a;
  uint32_t size;
  int i;


  for (i = 0; i < N_MALLOC; ++i)
    {
      if (malloc_ptr[i] == _a)
        {
          malloc_ptr[i] = NULL;
          malloc_line[i] = 0;
          break;
        }
    }

  if (i == N_MALLOC)
    {
      printk (KERN_ERR "MEMORY NOT FROM KMALLOC argo.c line %d\n", line);
    }

  if ((!a) || (a < (uint8_t *) 0x10000))
    {
      printk (KERN_ERR "MEMORY BUG argo.c line %d\n", line);
    }

  size = *(uint32_t *) (a - 4);

  if (MAGIC != *(uint32_t *) (a + size))
    {
      printk (KERN_ERR "MEMORY OVERWRITE argo.c line %d\n", line);
    }
  total -= size;


  kfree (a - 4);
}


static void *
do_argo_kmalloc (uint32_t size, int flags, int line)
{
  uint8_t *ret;
  int i;

  ret = kmalloc (size + 8, flags);
  if (!ret)
    return ret;

  total += size;

  if (total > big_total)
    {
      printk (KERN_ERR "argo memory usage now %d\n", total);
      big_total += 1024 * 1024;
      malloc_profile ();
    }

  ret += 4;

  *(uint32_t *) (ret - 4) = size;
  *(uint32_t *) (ret + size) = MAGIC;


  for (i = 0; i < N_MALLOC; ++i)
    {
      if (!malloc_ptr[i])
        {
          malloc_ptr[i] = ret;
          malloc_line[i] = line;
          break;
        }
    }

  return ret;
}
#else /* ! 0 */

#define argo_kfree kfree
#define argo_kmalloc kmalloc

#if (LINUX_VERSION_CODE > KERNEL_VERSION(3,9,0))
# define argo_random32 prandom_u32
#else /* LINUX_VERSION_CODE < KERNEL_VERSION(3,9,0) */
# define argo_random32 random32
#endif

#endif /* 0 */


static void
argo_hexdump (volatile void *_b, int len)
{
    volatile uint8_t *b = _b;
    int s = 0;
    int e = len;
    int i, j;
    uint8_t zero[16] = { 0 };

    int zeros = 0;

    for (i = 0; i < (e + 15); i += 16)
    {
        if ((i + sizeof(zero)) <= e)
        {
            if (!memcmp ((void *) &b[i], zero, sizeof(zero)))
                zeros++;
            else
                zeros = 0;
        }
        else
            zeros = 0;

        if (zeros == 2)
            printk (KERN_ERR "*\n");

        if (zeros >= 2)
            continue;


        printk (KERN_ERR "  %08x:", i);
        for (j = 0; j < 16; ++j)
        {
            int k = i + j;
            if (j == 8)
                printk (" ");
            if ((k >= s) && (k < e))
                printk ("%02x", b[k]);
            else
                printk ("  ");

        }
        printk ("  ");

        for (j = 0; j < 16; ++j)
        {
            int k = i + j;
            if (j == 8)
                printk (" ");
            if ((k >= s) && (k < e))
                printk ("%c", ((b[k] > 32) && (b[k] < 127)) ? b[k] : '.');
            else
                printk (" ");

        }
        printk ("\n");
    }
}

static void
summary_ring (struct ring *r)
{
    printk(KERN_ERR "ring at %p:\n", r);

    printk(KERN_ERR " xen_pfn_array_t at %p for %d:\n",
           r->gfn_array, r->npfns);

    printk(KERN_ERR " xen_argo_ring_t at %p:\n", r->ring);
    printk(KERN_ERR "  r->rx_ptr=%d r->tx_ptr=%d r->len=%d\n",
           r->ring->rx_ptr, r->ring->tx_ptr, r->len);
}

static void
dump_ring (struct ring *r)
{
  summary_ring (r);

  argo_hexdump (r->ring->ring, r->len);
}

/****************** hypercall ops *************************************/

static int
H_argo_register_ring(xen_argo_register_ring_t *r,
                     xen_argo_gfn_t *arr,
                     uint32_t len, uint32_t flags)
{
    (void)(*(volatile int*)r);
    return HYPERVISOR_argo_op(XEN_ARGO_OP_register_ring, r, arr, len, flags);
}

static int
H_argo_unregister_ring (xen_argo_unregister_ring_t *r)
{
    (void)(*(volatile int*)r);
    return HYPERVISOR_argo_op(XEN_ARGO_OP_unregister_ring, r, NULL, 0, 0);
}

static int
H_argo_sendv(xen_argo_addr_t *s, xen_argo_addr_t *d,
             const xen_argo_iov_t *iovs, uint32_t niov,
             uint32_t protocol)
{
    xen_argo_send_addr_t send;
    send.dst = *d;
    send.src = *s;
    send.src.pad = 0;
    send.dst.pad = 0;
    return HYPERVISOR_argo_op(XEN_ARGO_OP_sendv,
                              &send, (void *)iovs, niov, protocol);
}

static int
H_argo_notify(xen_argo_ring_data_t *rd)
{
    return HYPERVISOR_argo_op(XEN_ARGO_OP_notify, rd, NULL, 0, 0);
}

static int
H_viptables_add(xen_argo_viptables_rule_t* rule, int position)
{
    return HYPERVISOR_argo_op(XEN_ARGO_OP_viptables_add, rule, NULL, 0,
                              position);
}

static int
H_viptables_del(xen_argo_viptables_rule_t* rule, int position)
{
    return HYPERVISOR_argo_op(XEN_ARGO_OP_viptables_del, rule, NULL, 0,
                              position);
}

static int
H_viptables_list(xen_argo_viptables_list_t *rules_list)
{
    return HYPERVISOR_argo_op(XEN_ARGO_OP_viptables_list, rules_list, NULL, 0,
                              0);
}

/*********************port/ring uniqueness **********/

/*Need to hold write lock for all of these*/

static int
argo_id_in_use(struct argo_ring_id *id)
{
    struct ring *r;
    list_for_each_entry (r, &ring_list, node)
    {
        if ( (r->id.aport == id->aport) &&
             (r->id.partner_id == id->partner_id) )
            return 1;
    }
    return 0;
}

static xen_argo_port_t
argo_port_in_use(xen_argo_port_t aport, xen_argo_port_t *max)
{
    xen_argo_port_t ret = 0;
    struct ring *r;
    list_for_each_entry (r, &ring_list, node)
    {
        if ( r->id.aport == aport )
            ret++;
        if ( max && (r->id.aport > *max) )
            *max = r->id.aport;
    }
    return ret;
}

static xen_argo_port_t
argo_random_port(void)
{
    xen_argo_port_t port;
    port = argo_random32();
    port |= 0x80000000U;
    if ( port > 0xf0000000U )
        port -= 0x10000000;
    return port;
}

static const xen_argo_port_t ARGO_PORTS_EXHAUSTED = 0xffffffffU;

/*caller needs to hold lock*/
static xen_argo_port_t
argo_find_spare_port_number (void)
{
    xen_argo_port_t port, max = 0x80000000U;

    port = argo_random_port();
    if ( !argo_port_in_use(port, &max) )
        return port;
    else
        port = max + 1;

  return port;
}

/******************************ring goo ***************/

static int
register_ring(struct ring *r)
{
    xen_argo_register_ring_t reg;

    /* flags are zero: allow reregistration of an existing ring */

#ifdef ARGO_DEBUG
  printk (KERN_ERR "%s:%d aport=%u domain_id=%d partner_id=%d\n",
          __FILE__, __LINE__,
          (unsigned int) r->id.aport,
          (int) r->id.domain_id, (int) r->id.partner_id);
#endif
    reg.aport = r->id.aport;
    reg.partner_id = r->id.partner_id;
    reg.len = r->len;
    reg.pad = 0;

    return H_argo_register_ring((void *) &reg, r->gfn_array,
                                r->npfns, 0);
}

static int
unregister_ring(struct ring *r)
{
    xen_argo_unregister_ring_t reg;
    reg.aport = r->id.aport;
    reg.partner_id = r->id.partner_id;
    reg.pad = 0;

    /* FIXME: void * : hmm... */
    return H_argo_unregister_ring((void *) &reg);
}

static void
refresh_gfn_array(struct ring *r)
{
    uint8_t *b = (void *)r->ring;
    unsigned int i;

    for ( i = 0; i < r->npfns; ++i )
    {
#if defined(CONFIG_X86_64) || defined(CONFIG_X86_32)
        r->gfn_array[i] = pfn_to_mfn(vmalloc_to_pfn(b));
#else
        r->gfn_array[i] = pfn_to_gfn(vmalloc_to_pfn(b));
#endif
        b += PAGE_SIZE;
    }
}

static int
allocate_gfn_array(struct ring *r)
{
    uint32_t n = (r->len + PAGE_SIZE - 1) >> PAGE_SHIFT;
    size_t len = n * sizeof(xen_argo_gfn_t);

    r->gfn_array = argo_kmalloc(len, GFP_KERNEL);
    if ( !r->gfn_array )
        return -ENOMEM;

    memset(r->gfn_array, 0, len);
    r->npfns = n;

    refresh_gfn_array(r);
    return 0;
}

static int
allocate_ring(struct ring *r, int ring_len)
{
    int len;
    int ret = 0;

    do
    {
        if ( (ring_len > XEN_ARGO_MAX_RING_SIZE) ||
             (ring_len != XEN_ARGO_ROUNDUP(ring_len)) )
        {
#ifdef ARGO_DEBUG
            printk (KERN_ERR "ring_len=%d\n", ring_len);
#endif
            DEBUG_BANANA;
            ret = -EINVAL;
            break;
        }

        r->ring = NULL;
        r->gfn_array = NULL;
        r->order = 0;

        len = ring_len + sizeof(xen_argo_ring_t);
        r->order = get_order(len);

        r->ring = vmalloc(len);
        if ( !r->ring )
        {
            DEBUG_BANANA;
            ret = -ENOMEM;
            break;
        }

        // If this was exported it would be the perfect solution..
        // vmalloc_sync_all();
        memset((void *) r->ring, 0, len);

        r->len = ring_len;
        r->ring->rx_ptr = r->ring->tx_ptr = 0;

        memset((void *) r->ring->ring, 0x5a, ring_len);

        ret = allocate_gfn_array(r);
        if ( ret )
        {
            DEBUG_BANANA;
            break;
        }
        return 0;
    }
    while (1 == 0);

    /* Error exit, tidy up */
    if ( r->ring )
        vfree(r->ring);
    r->ring = NULL;

    if (r->gfn_array)
        argo_kfree (r->gfn_array);
    r->gfn_array = NULL;

  return ret;
}

/*Caller must hold lock*/
static void
recover_ring(struct ring *r)
{
    DEBUG_BANANA;

    /*It's all gone horribly wrong*/
    WARN(1, "argo: something went horribly wrong in a ring - dumping and attempting a recovery\n");
    dump_ring (r);

    /* Xen updates tx_ptr atomically to always be pointing somewhere sensible */
    r->ring->rx_ptr = r->ring->tx_ptr;
}


/* Caller must hold no locks. Ring is allocated with a refcnt of 1. */
static int
new_ring(struct argo_private *sponsor, struct argo_ring_id *pid)
{
    struct argo_ring_id id = *pid;
    struct ring *r;
    int ret;
    unsigned long flags;

    DEBUG_APPLE;

    if ( id.domain_id != XEN_ARGO_DOMID_ANY )
        return -EINVAL;

    DEBUG_APPLE;

    r = argo_kmalloc(sizeof(struct ring), GFP_KERNEL);
    DEBUG_APPLE;
    if ( !r )
        return -ENOMEM;
    DEBUG_APPLE;
    memset (r, 0, sizeof(struct ring));
    DEBUG_APPLE;

#ifdef ARGO_DEBUG
    printk(KERN_ERR "new_ring: %d\n", sponsor->desired_ring_size);
#endif

    ret = allocate_ring(r, sponsor->desired_ring_size);

#ifdef ARGO_DEBUG
    printk(KERN_ERR "new_ring: allocate_ring ret: %d\n", ret);
#endif

    DEBUG_APPLE;
    if ( ret )
    {
        DEBUG_APPLE;
        argo_kfree(r);
        return ret;
    }
    DEBUG_APPLE;

    INIT_LIST_HEAD(&r->privates);
    argo_spin_lock_init(&r->lock);
    atomic_set(&r->refcnt, 1);

    DEBUG_APPLE;
    do
    {
        /* ret = -EINVAL; argo_kfree(r); return ret; DISABLE */

        argo_write_lock_irqsave (&list_lock, flags);
        DEBUG_APPLE;
        if ( sponsor->state != ARGO_STATE_IDLE )
        {
            DEBUG_APPLE;
            ret = -EINVAL;
            break;
        }

#ifdef ARGO_DEBUG
        printk(KERN_ERR "fox %u\n", id.aport);
#endif

        DEBUG_APPLE;
        if ( !id.aport )
        {
            DEBUG_APPLE;
            id.aport = argo_find_spare_port_number ();
            DEBUG_APPLE;
            if ( id.aport == ARGO_PORTS_EXHAUSTED )
            {
                DEBUG_APPLE;
                ret = -ENOSPC;
                break;
            }
        }
        else if ( argo_id_in_use (&id) )
        {
            DEBUG_APPLE;
            ret = -EADDRINUSE;
            break;
        }

        DEBUG_APPLE;
        r->id.domain_id = id.domain_id;
        r->id.aport = id.aport;
        r->id.partner_id = id.partner_id;
        r->len = sponsor->desired_ring_size;
        r->sponsor = sponsor;
        sponsor->r = r;
        sponsor->state = ARGO_STATE_BOUND;


        DEBUG_APPLE;
        ret = register_ring(r);
        DEBUG_APPLE;
        if ( ret )
            break;

        DEBUG_APPLE;

        list_add(&r->node, &ring_list);
        DEBUG_APPLE;
        argo_write_unlock_irqrestore(&list_lock, flags);
        DEBUG_APPLE;
        return 0;
    }
    while (0);

    DEBUG_APPLE;
    argo_write_unlock_irqrestore(&list_lock, flags);

    DEBUG_APPLE;
    vfree(r->ring);
    DEBUG_APPLE;
    argo_kfree(r->gfn_array);
    DEBUG_APPLE;
    argo_kfree(r);

    DEBUG_APPLE;
    sponsor->r = NULL;
    sponsor->state = ARGO_STATE_IDLE;

    DEBUG_APPLE;
    return ret;
}

static void
free_ring (struct ring *r)
{
    vfree(r->ring);
    argo_kfree(r->gfn_array);
    argo_kfree(r);
}

/* Cleans up old rings */
static void
delete_ring(struct ring *r)
{
    int ret;
    if ( r->sponsor )
        MOAN;
    if ( !list_empty (&r->privates) )
        MOAN;

    list_del (&r->node);

    if ( (ret = unregister_ring(r)) )
        printk(KERN_ERR "unregister_ring hypercall failed: %d.\n", ret);
}


/* Returns !0 if you sucessfully got a reference to the ring */
static int
get_ring(struct ring *r)
{
    return atomic_add_unless(&r->refcnt, 1, 0);
}

/* must be called with DEBUG_WRITELOCK; argo_write_lock */
static int
put_ring(struct ring *r)
{
    if ( !r )
        return 0;

    if ( atomic_dec_and_test(&r->refcnt) )
    {
        delete_ring(r);
        return 1;
    }
    return 0;
}

/* caller must hold ring_lock */
static struct ring *
find_ring_by_id(struct argo_ring_id *id)
{
    struct ring *r;
    list_for_each_entry(r, &ring_list, node)
    {
        if ( (r->id.domain_id == id->domain_id) &&
             (r->id.aport == id->aport) &&
             (r->id.partner_id == id->partner_id) )
            return r;
    }
    return NULL;
}

/* caller must hold ring_lock */
struct ring *
find_ring_by_id_type(struct argo_ring_id *id, argo_rtype t)
{
    struct ring *r;
    list_for_each_entry (r, &ring_list, node)
    {
        if ( r->type != t )
            continue;

        if ( (r->id.domain_id == id->domain_id) &&
             (r->id.aport == id->aport) &&
             (r->id.partner_id == id->partner_id) )
            return r;
    }
    return NULL;
}

/************************ pending xmits ********************/


/*caller must hold pending_xmit_lock*/

static void
xmit_queue_wakeup_private(struct argo_ring_id *from,
                          uint32_t conid, xen_argo_addr_t *to, int len,
                          int delete)
{
    struct pending_xmit *p;

    list_for_each_entry(p, &pending_xmit_list, node)
    {
        if ( (p->type != ARGO_PENDING_XMIT_WAITQ_MATCH_PRIVATES) ||
             (p->conid != conid) )
            continue;

        if ( (from->domain_id == p->from.domain_id) &&
             (from->aport == p->from.aport) &&
             (from->partner_id == p->from.partner_id)
        &&   (to->domain_id == p->to.domain_id) &&
             (to->aport == p->to.aport) )
        {
            if ( delete )
            {
                atomic_dec (&pending_xmit_count);
                list_del (&p->node);
            }
            else
                p->len = len;

            return;
        }
    }

    if ( delete )
        return;

    p = argo_kmalloc( sizeof(struct pending_xmit), GFP_ATOMIC );
    if ( !p )
    {
        printk(KERN_ERR
               "Out of memory trying to queue an xmit sponsor wakeup\n");
        return;
    }
    p->type = ARGO_PENDING_XMIT_WAITQ_MATCH_PRIVATES;
    p->conid = conid;
    p->from = *from;
    p->to = *to;
    p->len = len;

    atomic_inc(&pending_xmit_count);
    list_add_tail(&p->node, &pending_xmit_list);
}

/*caller must hold pending_xmit_lock*/
static void
xmit_queue_wakeup_sponsor(struct argo_ring_id *from, xen_argo_addr_t * to, int len,
                          int delete)
{
    struct pending_xmit *p;

    list_for_each_entry(p, &pending_xmit_list, node)
    {
        if ( p->type != ARGO_PENDING_XMIT_WAITQ_MATCH_SPONSOR )
            continue;

        if ( (from->domain_id == p->from.domain_id) &&
             (from->aport == p->from.aport) &&
             (from->partner_id == p->from.partner_id)
        &&   (to->domain_id == p->to.domain_id) &&
             (to->aport == p->to.aport) )
        {
            if (delete)
            {
                atomic_dec(&pending_xmit_count);
                list_del(&p->node);
            }
            else
                p->len = len;
            return;
        }
    }

    if ( delete )
        return;


    p = argo_kmalloc(sizeof(struct pending_xmit), GFP_ATOMIC);
    if ( !p )
    {
        printk(KERN_ERR
               "Out of memory trying to queue an xmit sponsor wakeup\n");
        return;
    }
    p->type = ARGO_PENDING_XMIT_WAITQ_MATCH_SPONSOR;
    p->from = *from;
    p->to = *to;
    p->len = len;
    atomic_inc(&pending_xmit_count);
    list_add_tail(&p->node, &pending_xmit_list);
}

static int
xmit_queue_inline(struct argo_ring_id *from, xen_argo_addr_t *to,
                  void *buf, size_t len, uint32_t protocol)
{
    ssize_t ret;
    unsigned long flags;
    xen_argo_iov_t iov;
    struct pending_xmit *p;
    xen_argo_addr_t addr;

    DEBUG_APPLE;
    argo_spin_lock_irqsave (&pending_xmit_lock, flags);
    DEBUG_APPLE;

    iov.iov_hnd = buf;
#ifdef CONFIG_ARM
    iov.pad2 = 0;
#endif

    iov.iov_len = len;
    iov.pad = 0;

    addr.aport = from->aport;
    addr.domain_id = from->domain_id;
    addr.pad = 0;

    ret = H_argo_sendv(&addr, to, &iov, 1, protocol);
    DEBUG_APPLE;
    if (ret != -EAGAIN)
    {
        DEBUG_APPLE;
        argo_spin_unlock_irqrestore(&pending_xmit_lock, flags);
        return ret;
    }
    DEBUG_APPLE;

    p = argo_kmalloc(sizeof(struct pending_xmit) + len, GFP_ATOMIC);
    if ( !p )
    {
        argo_spin_unlock_irqrestore (&pending_xmit_lock, flags);
        printk(KERN_ERR
               "Out of memory trying to queue an xmit of %zu bytes\n", len);
        DEBUG_BANANA;
        return -ENOMEM;
    }

    p->type = ARGO_PENDING_XMIT_INLINE;
    p->from = *from;
    p->to = *to;
    p->len = len;
    p->protocol = protocol;

    if ( len )
        memcpy(p->data, buf, len);

    list_add_tail (&p->node, &pending_xmit_list);
    atomic_inc (&pending_xmit_count);
    argo_spin_unlock_irqrestore (&pending_xmit_lock, flags);

    return len;
}

static void
xmit_queue_rst_to(struct argo_ring_id *from, uint32_t conid, xen_argo_addr_t * to)
{
    struct argo_stream_header sh;

    if ( !to )
        return;

    sh.conid = conid;
    sh.flags = ARGO_SHF_RST;

    xmit_queue_inline(from, to, &sh, sizeof(sh), ARGO_PROTO_STREAM);
}

/*rx*/

static int
copy_into_pending_recv(struct ring *r, int len, struct argo_private *p)
{
    struct pending_recv *pending;
    int k;
    DEBUG_APPLE;

    /* Too much queued? Let the ring take the strain */
    if ( atomic_read(&p->pending_recv_count) > MAX_PENDING_RECVS )
    {
        argo_spin_lock(&p->pending_recv_lock);
        p->full = 1;
        argo_spin_unlock(&p->pending_recv_lock);

        return -1;
    }
    DEBUG_APPLE;

    pending = argo_kmalloc(sizeof(struct pending_recv) -
                             sizeof(struct argo_stream_header) + len,
                           GFP_ATOMIC);
    DEBUG_APPLE;
    if ( !pending )
        return -1;
    DEBUG_APPLE;

    pending->data_ptr = 0;
    pending->data_len = len - sizeof(struct argo_stream_header);
    DEBUG_APPLE;

    k = argo_copy_out(r->ring, r->len, &pending->from, NULL, &pending->sh,
                      len, 1);
    DEBUG_APPLE;

    DEBUG_RING(r);
    DEBUG_APPLE;

#ifdef ARGO_DEBUG
    DEBUG_ORANGE ("inserting into pending");
    printk(KERN_ERR "IP p=%p k=%d s=%d c=%d\n", pending, k, p->state,
           atomic_read (&p->pending_recv_count));
    /*argo_hexdump (&pending->sh, len);*/
    DEBUG_APPLE;
#endif

    argo_spin_lock(&p->pending_recv_lock);
    list_add_tail(&pending->node, &p->pending_recv_list);
    atomic_inc(&p->pending_recv_count);
    p->full = 0;
    argo_spin_unlock (&p->pending_recv_lock);
    DEBUG_APPLE;

    return 0;
}

/*******************************************notify *********************************/


/*caller must hold list_lock*/
static void
wakeup_privates(struct argo_ring_id *id, xen_argo_addr_t * peer, uint32_t conid)
{
    struct argo_private *p;

    struct ring *r = find_ring_by_id_type (id, ARGO_RTYPE_LISTENER);
    if ( !r )
        return;

    list_for_each_entry (p, &r->privates, node)
    {
        if ( (p->conid == conid) &&
             (peer->domain_id == p->peer.domain_id) &&
             (peer->aport == p->peer.aport) )
        {
            p->send_blocked = 0;
            wake_up_interruptible_all(&p->writeq);
            return;
        }
    }
}

/*caller must hold list_lock*/
static void
wakeup_sponsor(struct argo_ring_id *id)
{
    struct ring *r = find_ring_by_id(id);
    if ( !r  || !r->sponsor )
        return;

    r->sponsor->send_blocked = 0;
    wake_up_interruptible_all(&r->sponsor->writeq);
}

static void
argo_null_notify(void)
{
    H_argo_notify(NULL);
}

/*caller must hold list_lock*/
static void
argo_notify(void)
{
    unsigned long flags;
    int ret;
    int nent;
    struct pending_xmit *p, *n;
    xen_argo_ring_data_t *d;
    int i = 0;

    DEBUG_APPLE;
    argo_spin_lock_irqsave(&pending_xmit_lock, flags);
    DEBUG_APPLE;
    nent = atomic_read(&pending_xmit_count);
    DEBUG_APPLE;

    d = argo_kmalloc(sizeof(xen_argo_ring_data_t) +
                     nent * sizeof(xen_argo_ring_data_ent_t), GFP_ATOMIC);
    DEBUG_APPLE;
    if ( !d )
    {
        DEBUG_APPLE;
        argo_spin_unlock_irqrestore(&pending_xmit_lock, flags);
        return;
    }

    memset(d, 0, sizeof(xen_argo_ring_data_t));
    DEBUG_APPLE;

    list_for_each_entry(p, &pending_xmit_list, node)
    {
        DEBUG_APPLE;
        if (i != nent)
        {
            d->data[i].ring = p->to;
            d->data[i].space_required = p->len;
            i++;
        }
    }

    d->nent = i;
    DEBUG_APPLE;

    if ( H_argo_notify(d) )
    {
        DEBUG_APPLE;
        DEBUG_BANANA;
        argo_kfree(d);
        argo_spin_unlock_irqrestore(&pending_xmit_lock, flags);
        MOAN;
        return;
    }

    DEBUG_APPLE;

    i = 0;
    list_for_each_entry_safe(p, n, &pending_xmit_list, node)
    {
        int processed = 1;

        DEBUG_APPLE;
        if ( i == nent )
            continue;
        DEBUG_APPLE;

        if (d->data[i].flags & XEN_ARGO_RING_EXISTS)
        {
            switch ( p->type )
            {
                case ARGO_PENDING_XMIT_INLINE:
                {
                    xen_argo_iov_t iov;
                    xen_argo_addr_t addr;

                    if ( !(d->data[i].flags & XEN_ARGO_RING_SUFFICIENT) )
                    {
                        processed = 0;
                        break;
                    }

                    iov.iov_hnd = p->data;
#ifdef CONFIG_ARM
                    iov.pad2 = 0;
#endif
                    iov.iov_len = p->len;
                    iov.pad = 0;

                    addr.aport = p->from.aport;
                    addr.domain_id = p->from.domain_id;
                    addr.pad = 0;
                    ret = H_argo_sendv(&addr, &p->to, &iov, 1, p->protocol);

                    if ( ret == -EAGAIN )
                        processed = 0;

                    break;
                }
                case ARGO_PENDING_XMIT_WAITQ_MATCH_SPONSOR:
                {
                    DEBUG_APPLE;
                    if ( d->data[i].flags & XEN_ARGO_RING_SUFFICIENT )
                    {
    //  printk(KERN_ERR "wanted %d flags %x - doing wakeup and removing from q\n",d->data[i].space_required,d->data[i].flags); 
                        wakeup_sponsor (&p->from);
                    }
                    else
                    {
    //  printk(KERN_ERR "wanted %d flags %x - leaving in q\n",d->data[i].space_required,d->data[i].flags);
                        processed = 0;
                    }
                    break;
                }
                case ARGO_PENDING_XMIT_WAITQ_MATCH_PRIVATES:
                {
                    DEBUG_APPLE;
                    if (d->data[i].flags & XEN_ARGO_RING_SUFFICIENT)
                        wakeup_privates (&p->from, &p->to, p->conid);
                    else
                        processed = 0;
                    break;
                }
            }
        }

        if ( processed )
        {
            list_del(&p->node);    /*No one to talk to */
            atomic_dec(&pending_xmit_count);
            kfree(p);
        }
        DEBUG_APPLE;
        i++;
    }
    DEBUG_APPLE;

    argo_spin_unlock_irqrestore(&pending_xmit_lock, flags);
    DEBUG_APPLE;

    argo_kfree (d);
    DEBUG_APPLE;
}

/***********************  viptables ********************/
static int
viptables_add(struct argo_private *p, struct xen_argo_viptables_rule* rule,
              int position)
{
    return H_viptables_add(rule, position);
}

static int
viptables_del(struct argo_private *p, struct xen_argo_viptables_rule* rule,
              int position)
{
    return H_viptables_del(rule, position);
}

static int
viptables_list(struct argo_private *p,
               struct xen_argo_viptables_list *rules_list)
{
    return H_viptables_list(rules_list);
}

/***********************  state machines ********************/
static int
connector_state_machine(struct argo_private *p, struct argo_stream_header *sh)
{
    if ( sh->flags & ARGO_SHF_ACK )
    {
        switch (p->state)
        {
            case ARGO_STATE_CONNECTING:
            {
                p->state = ARGO_STATE_CONNECTED;

                argo_spin_lock(&p->pending_recv_lock);
                p->pending_error = 0;
                argo_spin_unlock(&p->pending_recv_lock);

                wake_up_interruptible_all(&p->writeq);
                return 0;
            }
            case ARGO_STATE_CONNECTED:
            case ARGO_STATE_DISCONNECTED:
            {
                p->state = ARGO_STATE_DISCONNECTED;

                wake_up_interruptible_all (&p->readq);
                wake_up_interruptible_all (&p->writeq);
                return 1;             /*Send RST */
            }
            default:
                break;
        }
    }

    if ( sh->flags & ARGO_SHF_RST )
    {
        switch (p->state)
        {
            case ARGO_STATE_CONNECTING:
            {
                argo_spin_lock(&p->pending_recv_lock);
                p->pending_error = -ECONNREFUSED;
                argo_spin_unlock(&p->pending_recv_lock);
            }
                /* fall through */
            case ARGO_STATE_CONNECTED:
            {
                p->state = ARGO_STATE_DISCONNECTED;
                wake_up_interruptible_all (&p->readq);
                wake_up_interruptible_all (&p->writeq);
                return 0;
            }
            default:
                break;
            }
        }
    return 0;
}

static void
acceptor_state_machine(struct argo_private *p, struct argo_stream_header *sh)
{
    if ( (sh->flags & ARGO_SHF_RST) && ((p->state == ARGO_STATE_ACCEPTED)) )
    {
        p->state = ARGO_STATE_DISCONNECTED;
        wake_up_interruptible_all(&p->readq);
        wake_up_interruptible_all(&p->writeq);
    }
}

/************************ interrupt handler ******************/

static int
connector_interrupt(struct ring *r)
{
    ssize_t msg_len;
    uint32_t protocol;
    struct argo_stream_header sh;
    xen_argo_addr_t from;
    int ret = 0;

    if ( !r->sponsor )
    {
        MOAN;
        return -1;
    }

    /* Peek the header */
    msg_len = argo_copy_out(r->ring, r->len, &from, &protocol, &sh,
                            sizeof(sh), 0);

    if ( msg_len == -1 )
    {
        DEBUG_APPLE;
        recover_ring(r);
        return ret;
    }

    /* This is a connector: no-one should send SYN, so send RST back */
    if ( sh.flags & ARGO_SHF_SYN )   
    {
        msg_len = argo_copy_out(r->ring, r->len, &from, &protocol, &sh,
                                sizeof(sh), 1);
        if ( msg_len == sizeof(sh) )
            xmit_queue_rst_to(&r->id, sh.conid, &from);
        return ret;
    }

    /* Right connexion? */
    if ( sh.conid != r->sponsor->conid )
    {
        msg_len = argo_copy_out(r->ring, r->len, &from, &protocol, &sh,
                                sizeof(sh), 1);
        xmit_queue_rst_to(&r->id, sh.conid, &from);
        return ret;
    }

    /* Any messages to eat? */
    if ( sh.flags & (ARGO_SHF_ACK | ARGO_SHF_RST) )
    {
        msg_len = argo_copy_out(r->ring, r->len, &from, &protocol, &sh,
                                sizeof(sh), 1);
        if ( msg_len == sizeof(sh) )
        {
            if ( connector_state_machine(r->sponsor, &sh) )
                xmit_queue_rst_to (&r->id, sh.conid, &from);
        }
        return ret;
    }

  //FIXME set a flag to say wake up the userland process next time, and do that rather than copy
    ret = copy_into_pending_recv(r, msg_len, r->sponsor);
    wake_up_interruptible_all(&r->sponsor->readq);

    return ret;
}

static int
acceptor_interrupt (struct argo_private *p, struct ring *r,
                    struct argo_stream_header *sh, ssize_t msg_len)
{
    xen_argo_addr_t from;
    int ret = 0;

    DEBUG_APPLE;
    /*This is an acceptor: no-one should send SYN or ACK, so send RST back */
    if ( sh->flags & (ARGO_SHF_SYN | ARGO_SHF_ACK) )
    {
        DEBUG_APPLE;
        msg_len = argo_copy_out(r->ring, r->len, &from, NULL, sh,
                                sizeof(*sh), 1);
        if ( msg_len == sizeof(*sh) )
            xmit_queue_rst_to (&r->id, sh->conid, &from);
        return ret;
    }

    DEBUG_APPLE;
    /* Is it all over? */
    if ( sh->flags & ARGO_SHF_RST )
    {
        /*Consume the RST */
        msg_len = argo_copy_out(r->ring, r->len, &from, NULL, sh,
                                sizeof(*sh), 1);
        if ( msg_len == sizeof(*sh) )
            acceptor_state_machine(p, sh);
        return ret;
    }

    DEBUG_APPLE;
    /*Copy the message out */
    ret = copy_into_pending_recv(r, msg_len, p);
    DEBUG_APPLE;
    wake_up_interruptible_all(&p->readq);
    DEBUG_APPLE;
    return ret;
}

static int
listener_interrupt(struct ring *r)
{
    int ret = 0;
    ssize_t msg_len;
    uint32_t protocol;
    struct argo_stream_header sh;
    struct argo_private *p;
    xen_argo_addr_t from;

    DEBUG_APPLE;
    DEBUG_RING(r);

    /*Peek the header */
    msg_len = argo_copy_out(r->ring, r->len, &from, &protocol, &sh,
                            sizeof(sh), 0);
    DEBUG_APPLE;

    if (msg_len == -1)
    {
        DEBUG_APPLE;
        recover_ring(r);
        return ret;
    }
    DEBUG_APPLE;

    if ( (protocol != ARGO_PROTO_STREAM) || (msg_len < sizeof (sh)) )
    {
      DEBUG_APPLE;
      /* Wrong protocol so bin it */
      (void) argo_copy_out (r->ring, r->len, NULL, NULL, NULL, 0, 1);
      return ret;
    }
    DEBUG_APPLE;

    list_for_each_entry(p, &r->privates, node)
    {
        DEBUG_APPLE;
        if ( (p->conid == sh.conid) &&
             (p->peer.domain_id == from.domain_id) &&
             (p->peer.aport == from.aport) )
        {
            DEBUG_APPLE;
            ret = acceptor_interrupt(p, r, &sh, msg_len);
            DEBUG_APPLE;
            return ret;
        }
    }
    DEBUG_APPLE;

    /*consume it */

    if ( sh.flags & ARGO_SHF_RST )
    {
        /*
        * JP: If we previously received a SYN which has not been pulled by
        * argo_accept() from the pending queue yet, the RST will be dropped here
        * and the connection will never be closed.
        * Hence we must make sure to evict the SYN header from the pending queue
        * before it gets picked up by argo_accept().
        */
        struct pending_recv *pending, *t;

        if ( r->sponsor )
        {
            argo_spin_lock(&r->sponsor->pending_recv_lock);
            list_for_each_entry_safe(pending, t, &r->sponsor->pending_recv_list,
                                     node)
            {
                DEBUG_APPLE;
                if ( pending->sh.flags & ARGO_SHF_SYN &&
                     pending->sh.conid == sh.conid )
                {
                    list_del(&pending->node);
                    atomic_dec(&r->sponsor->pending_recv_count);
                    argo_kfree(pending);
                    break;
                }
            }
            argo_spin_unlock(&r->sponsor->pending_recv_lock);
        }

        /* Rst to a listener, should be picked up above for the connexion, drop it */
        DEBUG_APPLE;
        (void) argo_copy_out(r->ring, r->len, NULL, NULL, NULL, sizeof(sh),
                             1);
        return ret;
    }
    DEBUG_APPLE;

    if ( sh.flags & ARGO_SHF_SYN )
    {
        DEBUG_APPLE;
        /* Syn to new connexion */
        if ( (!r->sponsor) || (msg_len != sizeof(sh)) )
        {
            (void) argo_copy_out(r->ring, r->len, NULL, NULL, NULL,
                                 sizeof(sh), 1);
            return ret;
        }

        DEBUG_APPLE;
        ret = copy_into_pending_recv(r, msg_len, r->sponsor);
        DEBUG_APPLE;
        wake_up_interruptible_all(&r->sponsor->readq);
        return ret;
    }
    DEBUG_APPLE;

    (void) argo_copy_out(r->ring, r->len, NULL, NULL, NULL, sizeof(sh), 1);
    /*Data for unknown destination, RST them */
    xmit_queue_rst_to(&r->id, sh.conid, &from);

    return ret;
}

static void
argo_interrupt_rx(void)
{
    struct ring *r;

    //DEBUG_ORANGE("a");
    DEBUG_APPLE;

    argo_read_lock(&list_lock);

    /* Wake up anyone pending*/
    list_for_each_entry(r, &ring_list, node)
    {
        if ( r->ring->tx_ptr == r->ring->rx_ptr )
            continue;

        switch (r->type)
        {
            case ARGO_RTYPE_IDLE:
                (void) argo_copy_out(r->ring, r->len, NULL, NULL, NULL, 1,
                                     1);
                break;

            case ARGO_RTYPE_DGRAM:
                /*For datagrams we just wake up the reader */
                if ( r->sponsor )
                    wake_up_interruptible_all(&r->sponsor->readq);
                break;

            case ARGO_RTYPE_CONNECTOR:
                argo_spin_lock(&r->lock);

                while ( (r->ring->tx_ptr != r->ring->rx_ptr)
                        && !connector_interrupt (r))
                    ;

                argo_spin_unlock(&r->lock);
                break;

            case ARGO_RTYPE_LISTENER:
                argo_spin_lock(&r->lock);

                while ((r->ring->tx_ptr != r->ring->rx_ptr)
                       && !listener_interrupt (r))
                    ;
                argo_spin_unlock (&r->lock);
                break;

            default: /*enum warning */
                break;
        }
    }
    argo_read_unlock (&list_lock);
}

static irqreturn_t
argo_interrupt(int irq, void *dev_id)
{
    unsigned long flags;

#ifdef ARGO_DEBUG
    DEBUG_ORANGE ("argo_interrupt");
#endif

    argo_spin_lock_irqsave(&interrupt_lock, flags);
    argo_interrupt_rx();


    DEBUG_APPLE;
    argo_notify();
    DEBUG_APPLE;

    argo_spin_unlock_irqrestore(&interrupt_lock, flags);
    return IRQ_HANDLED;
}

static void
argo_fake_irq(void)
{
    unsigned long flags;

    argo_spin_lock_irqsave(&interrupt_lock, flags);

    argo_interrupt_rx();
    argo_null_notify();

    argo_spin_unlock_irqrestore(&interrupt_lock, flags);
}



/******************************* file system gunge *************/

#define ARGOFS_MAGIC 0x4152474f  /* "ARGO" */

static struct vfsmount *argo_mnt = NULL;
static const struct file_operations argo_fops_stream;
static const struct dentry_operations argofs_dentry_operations;

#if ( LINUX_VERSION_CODE < KERNEL_VERSION(5,3,0) )
static struct dentry *
argofs_mount_pseudo(struct file_system_type *fs_type, int flags,
        const char *dev_name, void *data)
{
    return mount_pseudo(fs_type, "argo:", NULL, &argofs_dentry_operations,
                        ARGOFS_MAGIC);
}

#else /* LINUX_VERSION_CODE >= KERNEL_VERSION(5,3,0) */
static int argofs_init_fs_context(struct fs_context *fc)
{
    struct pseudo_fs_context *ctx;

    ctx = init_pseudo(fc, ARGOFS_MAGIC);
    if (!ctx)
        return -ENOMEM;
    ctx->dops = &argofs_dentry_operations;
    return 0;
}
#endif

static struct file_system_type argo_fs = {
    /* No owner field so module can be unloaded */
    .name = "argofs",
#if ( LINUX_VERSION_CODE < KERNEL_VERSION(5,3,0) )
    .mount = argofs_mount_pseudo,
#else /* LINUX_VERSION_CODE >= KERNEL_VERSION(5,3,0) */
    .init_fs_context = argofs_init_fs_context,
#endif
    .kill_sb = kill_litter_super
};

static int
setup_fs(void)
{
    int ret;

    ret = register_filesystem(&argo_fs);
    if ( ret )
    {
        printk(KERN_ERR "argofs: couldn't register tedious filesystem thingy\n");
        return ret;
    }

    argo_mnt = kern_mount (&argo_fs);
    if ( IS_ERR(argo_mnt) )
    {
        unregister_filesystem(&argo_fs);
        ret = PTR_ERR(argo_mnt);
        printk(KERN_ERR "argo: couldn't mount tedious filesystem thingy\n");
        return ret;
    }

    return 0;
}

static void
unsetup_fs (void)
{
    mntput(argo_mnt);
    unregister_filesystem(&argo_fs);
}

/*********************methods*************************/

static int stream_connected(struct argo_private *p)
{
    switch(p->state) {
        case ARGO_STATE_ACCEPTED:
        case ARGO_STATE_CONNECTED:
            return 1;
        default:
        return 0;
    }
}

static size_t
argo_try_send_sponsor(struct argo_private *p, xen_argo_addr_t *dest,
                      const void *buf, size_t len, uint32_t protocol)
{
    size_t ret;
    unsigned long flags;
    xen_argo_iov_t iov;
    xen_argo_addr_t addr;

    iov.iov_hnd = buf;
#ifdef CONFIG_ARM
    iov.pad2 = 0;
#endif
    iov.iov_len = len;
    iov.pad = 0;

    addr.aport = p->r->id.aport;
    addr.domain_id = p->r->id.domain_id;
    addr.pad = 0;

    DEBUG_APPLE;
    ret = H_argo_sendv(&addr, dest, &iov, 1, protocol);
    DEBUG_APPLE;

    argo_spin_lock_irqsave(&pending_xmit_lock, flags);
    if ( ret == -EAGAIN )
    {
        DEBUG_APPLE;
        /* Add pending xmit */
        xmit_queue_wakeup_sponsor(&p->r->id, dest, len, 0);
        DEBUG_APPLE;
        p->send_blocked++;
        DEBUG_APPLE;
    }
    else
    {
        DEBUG_APPLE;
        /* remove pending xmit */
        xmit_queue_wakeup_sponsor(&p->r->id, dest, len, 1);
        DEBUG_APPLE;
        p->send_blocked = 0;
    }
    DEBUG_APPLE;

    argo_spin_unlock_irqrestore(&pending_xmit_lock, flags);
    DEBUG_APPLE;
    return ret;
}


static size_t
argo_try_sendv_sponsor(struct argo_private *p,
                      xen_argo_addr_t * dest,
                      const xen_argo_iov_t *iovs, size_t niov, size_t len,
                      uint32_t protocol)
{
    size_t ret;
    unsigned long flags;
    xen_argo_addr_t addr;

    addr.aport = p->r->id.aport;
    addr.domain_id = p->r->id.domain_id;
    addr.pad = 0;

    DEBUG_APPLE;
    ret = H_argo_sendv(&addr, dest, iovs, niov, protocol);
    DEBUG_APPLE;

#ifdef ARGO_DEBUG
    printk (KERN_ERR "sendv returned %d\n", ret);
#endif

    argo_spin_lock_irqsave(&pending_xmit_lock, flags);
    if ( ret == -EAGAIN )
    {
        DEBUG_APPLE;
        /* Add pending xmit */
        xmit_queue_wakeup_sponsor(&p->r->id, dest, len, 0);
        DEBUG_APPLE;
        p->send_blocked++;
        DEBUG_APPLE;
    }
    else
    {
        DEBUG_APPLE;
        /* Remove pending xmit */
        xmit_queue_wakeup_sponsor(&p->r->id, dest, len, 1);
        DEBUG_APPLE;
        p->send_blocked = 0;
    }
    DEBUG_APPLE;

    argo_spin_unlock_irqrestore (&pending_xmit_lock, flags);
    DEBUG_APPLE;
    return ret;
}

/* 
 * Try to send from one of the ring's privates (not its sponsor),
 * and queue an writeq wakeup if we fail
 */
static size_t
argo_try_sendv_privates(struct argo_private *p, xen_argo_addr_t * dest,
                        const xen_argo_iov_t * iovs, size_t niov, size_t len,
                        uint32_t protocol)
{
    size_t ret;
    unsigned long flags;
    xen_argo_addr_t addr;

    addr.aport = p->r->id.aport;
    addr.domain_id = p->r->id.domain_id;
    addr.pad = 0;

    ret = H_argo_sendv(&addr, dest, iovs, niov, protocol);

    argo_spin_lock_irqsave(&pending_xmit_lock, flags);
    if ( ret == -EAGAIN )
    {
        /* Add pending xmit */
        xmit_queue_wakeup_private(&p->r->id, p->conid, dest, len, 0);
        p->send_blocked++;
    }
    else
    {
        /* Remove pending xmit */
        xmit_queue_wakeup_private(&p->r->id, p->conid, dest, len, 1);
        p->send_blocked = 0;
    }
    argo_spin_unlock_irqrestore(&pending_xmit_lock, flags);

    return ret;
}

static ssize_t
argo_sendto_from_sponsor(struct argo_private *p,
                         const void *buf, size_t len,
                         int nonblock, xen_argo_addr_t *dest,
                         uint32_t protocol)
{
    size_t ret = 0, ts_ret;

    do
    {
        switch (p->state)
        {
            case ARGO_STATE_CONNECTING:
                ret = -ENOTCONN;
                break;
            case ARGO_STATE_DISCONNECTED:
                ret = -EPIPE;
                break;
            case ARGO_STATE_BOUND:
            case ARGO_STATE_CONNECTED:
                break;
            default:
                ret = -EINVAL;
        }

        if ( len > (p->r->len - sizeof(struct xen_argo_ring_message_header)) )
            ret = -EMSGSIZE;
        DEBUG_APPLE;

        if ( ret )
            break;

        DEBUG_APPLE;
        if ( nonblock )
        {
            xen_argo_iov_t iov;
            xen_argo_addr_t addr;

            iov.iov_hnd = buf;
#ifdef CONFIG_ARM
            iov.pad2 = 0;
#endif
            iov.iov_len = len;
            iov.pad = 0;
            addr.aport = p->r->id.aport;
            addr.domain_id = p->r->id.domain_id;
            addr.pad = 0;

            ret = H_argo_sendv(&addr, dest, &iov, 1, protocol);

            DEBUG_APPLE;
            break;
        }
        DEBUG_APPLE;

//FIXME I happen to know that wait_event_interruptible will never
// evaluate the 2nd argument once it has returned true but I shouldn't

//The EAGAIN will cause xen to send an interrupt which will via the pending_xmit_list and writeq wake us up
        ret = wait_event_interruptible(p->writeq,
                  ((ts_ret = argo_try_send_sponsor(p, dest, buf, len,
                                                   protocol)) != -EAGAIN));
        DEBUG_APPLE;

        if ( ret )
            break;
        DEBUG_APPLE;

        ret = ts_ret;
    }
    while (0);
    DEBUG_APPLE;

    return ret;
}


static ssize_t
argo_stream_sendvto_from_sponsor(struct argo_private *p,
                          const xen_argo_iov_t *iovs, size_t niov, size_t len,
                          int nonblock, xen_argo_addr_t * dest, uint32_t protocol)
{
    size_t ret = 0, ts_ret;

    do
    {
        switch (p->state)
        {
            case ARGO_STATE_CONNECTING:
                ret = -ENOTCONN;
                break;
            case ARGO_STATE_DISCONNECTED:
                ret = -EPIPE;
                break;
            case ARGO_STATE_BOUND:
            case ARGO_STATE_CONNECTED:
                break;
            default:
                ret = -EINVAL;
        }

        if ( len > (p->r->len - sizeof(struct xen_argo_ring_message_header)) )
            ret = -EMSGSIZE;

        DEBUG_APPLE;

        if ( ret )
            break;

        DEBUG_APPLE;
        if ( nonblock )
        {
            xen_argo_addr_t addr;

            addr.aport = p->r->id.aport;
            addr.domain_id = p->r->id.domain_id;
            addr.pad = 0;

            ret = H_argo_sendv(&addr, dest, iovs, niov, protocol);
            DEBUG_APPLE;
            break;
        }
        DEBUG_APPLE;

//FIXME I happen to know that wait_event_interruptible will never
// evaluate the 2nd argument once it has returned true but I shouldn't

//The EAGAIN will cause xen to send an interrupt which will via the pending_xmit_list and writeq wake us up
        ret = wait_event_interruptible(p->writeq,
                  ((ts_ret = argo_try_sendv_sponsor(p, dest, iovs, niov, len,
                                                    protocol)) != -EAGAIN) ||
                  !stream_connected(p));
        DEBUG_APPLE;

        if ( ret )
            break;

        DEBUG_APPLE;

        ret = ts_ret;
    }
    while (0);
    DEBUG_APPLE;

    return ret;
}

static ssize_t
argo_stream_sendvto_from_private (struct argo_private *p,
                          const xen_argo_iov_t * iovs, size_t niov, size_t len,
                          int nonblock, xen_argo_addr_t *dest, uint32_t protocol)
{
    size_t ret = 0, ts_ret;

    do
    {
        switch (p->state)
        {
            case ARGO_STATE_DISCONNECTED:
                ret = -EPIPE;
                break;
            case ARGO_STATE_ACCEPTED:
                break;
            default:
                ret = -EINVAL;
        }

        if ( len > (p->r->len - sizeof(struct xen_argo_ring_message_header)) )
            ret = -EMSGSIZE;

        if (ret)
            break;

        if (nonblock)
        {
            xen_argo_addr_t addr;

            addr.aport = p->r->id.aport;
            addr.domain_id = p->r->id.domain_id;
            addr.pad = 0;

            ret = H_argo_sendv(&addr, dest, iovs, niov, protocol);
          break;
        }

//FIXME I happen to know that wait_event_interruptible will never
// evaluate the 2nd argument once it has returned true but I shouldn't

//The EAGAIN will cause xen to send an interrupt which will via the pending_xmit_list and writeq wake us up
        ret = wait_event_interruptible(p->writeq,
                  ((ts_ret = argo_try_sendv_privates(p, dest, iovs, niov, len,
                                                     protocol)) != -EAGAIN) ||
                  !stream_connected(p));
        if ( ret )
            break;

        ret = ts_ret;
    }
    while (0);

    return ret;
}

static int
argo_get_sock_type(struct argo_private *p, int *type)
{
    *type = p->ptype;
    return 0;
}

static int
argo_get_sock_name (struct argo_private *p, struct argo_ring_id *id)
{
    int rc = 0;

    argo_read_lock (&list_lock);

    if ( (p->r) && (p->r->ring) )
        *id = p->r->id;
    else
    {
        /* no need to actually fail here */
        id->partner_id = XEN_ARGO_DOMID_ANY;
        id->domain_id = XEN_ARGO_DOMID_ANY;
        id->aport = 0;
    }

    argo_read_unlock (&list_lock);

    return rc;
}

static int
argo_get_peer_name (struct argo_private *p, xen_argo_addr_t * id)
{
    int rc = 0;

    argo_read_lock (&list_lock);

    switch (p->state)
    {
        case ARGO_STATE_CONNECTING:
        case ARGO_STATE_CONNECTED:
        case ARGO_STATE_ACCEPTED:
        {
            *id = p->peer;
            break;
        }
        default:
          rc = -ENOTCONN;
    }

    argo_read_unlock (&list_lock);

    return rc;
}


static int
argo_set_ring_size(struct argo_private *p, uint32_t ring_size)
{

    if ( ring_size < (sizeof(struct xen_argo_ring_message_header) +
                      XEN_ARGO_ROUNDUP(1) + XEN_ARGO_ROUNDUP(1)))
        return -EINVAL;
    if ( ring_size != XEN_ARGO_ROUNDUP(ring_size) )
        return -EINVAL;

    argo_read_lock(&list_lock);

    if ( p->state != ARGO_STATE_IDLE )
    {
        argo_read_unlock (&list_lock);
        return -EINVAL;
    }
    p->desired_ring_size = ring_size;

    argo_read_unlock(&list_lock);

    return 0;
}


static ssize_t
argo_recvfrom_dgram(struct argo_private *p, void *buf, size_t len,
                    int nonblock, int peek, xen_argo_addr_t *src)
{
    ssize_t ret;
    uint32_t protocol;
    xen_argo_addr_t lsrc;

    if (!src)
        src = &lsrc;

    DEBUG_APPLE;
#ifdef ARGO_DEBUG
    printk("FISHSOUP argo_recvfrom_dgram %p %u %d %d \n", buf, len,
           nonblock, peek);
#endif

    argo_read_lock(&list_lock);

    DEBUG_APPLE;
    for (;;)
    {
        DEBUG_APPLE;

        if ( !nonblock )
        {
            /* drop the list lock while waiting */
            argo_read_unlock(&list_lock);

            ret = wait_event_interruptible(p->readq,
                                  (p->r->ring->rx_ptr != p->r->ring->tx_ptr));

            argo_read_lock(&list_lock);

            if ( ret )
                break;
        }

        DEBUG_APPLE;
        /*
         * For Dgrams, we know the interrupt handler will never use the ring,
         * so leave irqs on
         */
        argo_spin_lock(&p->r->lock); 

        if ( p->r->ring->rx_ptr == p->r->ring->tx_ptr )
        {
            argo_spin_unlock(&p->r->lock);

            DEBUG_APPLE;

            if ( nonblock )
            {
                DEBUG_APPLE;
                ret = -EAGAIN;
                break;
            }
            DEBUG_APPLE;

            continue;
        }

        DEBUG_APPLE;

        ret = argo_copy_out(p->r->ring, p->r->len, src, &protocol, buf, len,
                            !peek);
        if ( ret < 0 )
        {
            DEBUG_APPLE;
            recover_ring(p->r);

            argo_spin_unlock(&p->r->lock);

            continue;
        }
        argo_spin_unlock(&p->r->lock);

        if ( !peek )
            argo_null_notify();

        DEBUG_APPLE;
        if ( protocol != ARGO_PROTO_DGRAM )
        {
            /* If peeking consume the rubbish */
            if ( peek )
                (void) argo_copy_out(p->r->ring, p->r->len, NULL, NULL,
                                     NULL, 1, 1);

            continue;
        }

        DEBUG_APPLE;

        if ( ret >= 0 )
        {
            if ( (p->state == ARGO_STATE_CONNECTED) &&
                 ((p->peer.domain_id != src->domain_id) ||
                  (p->peer.aport != src->aport)) )
            {
                /* Wrong source - bin it */

                /* If peeking consume the rubbish */
                if ( peek )
                    (void) argo_copy_out(p->r->ring, p->r->len, NULL, NULL,
                                         NULL, 1, 1);

                ret = -EAGAIN;
                continue;
            }
            break;
        }
        DEBUG_APPLE;
    }
    DEBUG_APPLE;

    argo_read_unlock(&list_lock);
    DEBUG_APPLE;

    return ret;
}

static ssize_t
argo_recv_stream(struct argo_private *p, void *_buf, int len, int recv_flags,
                 int nonblock)
{
    size_t to_copy;
    size_t count = 0;
    int eat;
    int ret;
    unsigned long flags;
    int schedule_irq = 0;

    struct pending_recv *pending;
    uint8_t *buf = (void *) _buf;

    argo_read_lock(&list_lock);

    switch (p->state)
    {
        case ARGO_STATE_DISCONNECTED:
        {
            argo_read_unlock(&list_lock);
            return -EPIPE;
        }
        case ARGO_STATE_CONNECTING:
        {
            argo_read_unlock(&list_lock);
            return -ENOTCONN;
        }
        case ARGO_STATE_CONNECTED:
        case ARGO_STATE_ACCEPTED:
            break;
        default:
        {
            argo_read_unlock(&list_lock);
            return -EINVAL;
        }
    }

    for (;;)
    {

        DEBUG_APPLE;
        argo_spin_lock_irqsave(&p->pending_recv_lock, flags);
        DEBUG_APPLE;
        while ( !list_empty(&p->pending_recv_list) && len )
        {
            DEBUG_APPLE;
            pending = list_first_entry(&p->pending_recv_list,
                                       struct pending_recv, node);

            DEBUG_APPLE;
            if ( (pending->data_len - pending->data_ptr) > len )
            {
                DEBUG_APPLE;
                to_copy = len;
                eat = 0;
            }
            else
            {
                DEBUG_APPLE;
                eat = 1;
                to_copy = pending->data_len - pending->data_ptr;
            }

            DEBUG_APPLE;
            argo_spin_unlock_irqrestore(&p->pending_recv_lock, flags);

            if ( !access_ok_wrapper(VERIFY_WRITE, buf, to_copy) )
            {
                printk(KERN_ERR "ARGO - ERROR: buf invalid _buf=%p buf=%p len=%d to_copy=%zu count=%zu\n",
                       _buf, buf, len, to_copy, count);

                return count ? count: -EFAULT;
            }

            ret = copy_to_user(buf, &pending->data[pending->data_ptr], to_copy);
            if ( ret )
                printk(KERN_ERR "ARGO - copy_to_user failed: buf: %p other: %p to_copy: %lu pending %p data_ptr %lu data: %p\n",
                    buf, &pending->data[pending->data_ptr], to_copy, pending,
                    pending->data_ptr, pending->data);
                /* FIXME: error exit action here? */

            argo_spin_lock_irqsave(&p->pending_recv_lock, flags);

            if ( !eat )
            {
                DEBUG_APPLE;
                pending->data_ptr += to_copy;
            }
            else
            {
                DEBUG_APPLE;
                list_del (&pending->node);

#ifdef ARGO_DEBUG
                printk(KERN_ERR "OP p=%p k=%d s=%d c=%d\n", pending,
                       pending->data_len, p->state,
                       atomic_read (&p->pending_recv_count));
#endif
                argo_kfree (pending);
                atomic_dec(&p->pending_recv_count);

                if (p->full)
                    schedule_irq = 1;
            }

            DEBUG_APPLE;

            buf += to_copy;
            count += to_copy;
            len -= to_copy;
            DEBUG_APPLE;
        }
        argo_spin_unlock_irqrestore(&p->pending_recv_lock, flags);
        DEBUG_APPLE;

        argo_read_unlock(&list_lock);

#if 1
        if ( schedule_irq )
            argo_fake_irq ();
#endif

        if ( p->state == ARGO_STATE_DISCONNECTED )
        {
            DEBUG_APPLE;
            return count ? count : -EPIPE;
        }

        DEBUG_APPLE;

        /* Bizzare sockets TCP behavior */
        if ( count && !(recv_flags & MSG_WAITALL) )
            return count;


        if ( nonblock )
            return count ? count : -EAGAIN;

        DEBUG_APPLE;

        ret = wait_event_interruptible(p->readq,
                (!list_empty (&p->pending_recv_list) || !stream_connected(p)));

        DEBUG_APPLE;
        if ( ret )
            return count ? count : ret;

        DEBUG_APPLE;

        if ( !len )
            return count;

        DEBUG_APPLE;

        argo_read_lock (&list_lock);
    }
}

static ssize_t
argo_send_stream(struct argo_private *p, const void *_buf, int len,
                 int nonblock)
{
    int write_lump;
    const uint8_t *buf = _buf;
    size_t count = 0;
    ssize_t ret;
    int to_send;

    DEBUG_APPLE;

    write_lump = DEFAULT_RING_SIZE >> 2;

    switch (p->state)
    {
        case ARGO_STATE_DISCONNECTED:
        {
            DEBUG_APPLE;
            return -EPIPE;
        }
        case ARGO_STATE_CONNECTING:
        {
            return -ENOTCONN;
        }
        case ARGO_STATE_CONNECTED:
        case ARGO_STATE_ACCEPTED:
        {
            DEBUG_APPLE;
            break;
        }
        default:
        {
            DEBUG_APPLE;
            return -EINVAL;
        }
    }
    DEBUG_APPLE;
    DEBUG_APPLE;

    while ( len )
    {
        struct argo_stream_header sh;
        xen_argo_iov_t iovs[2];
        DEBUG_APPLE;

        to_send = len > write_lump ? write_lump 
                                   : len;

        sh.flags = 0;
        sh.conid = p->conid;

        iovs[0].iov_hnd = (void *) &sh;
        iovs[1].iov_hnd = (void *) buf;
#ifdef CONFIG_ARM
        iovs[0].pad2 = 0;
        iovs[1].pad2 = 0;
#endif
        iovs[0].iov_len = sizeof(sh);
        iovs[1].iov_len = to_send;
        iovs[0].pad = 0;
        iovs[1].pad = 0;

        DEBUG_APPLE;
        DEBUG_HEXDUMP((void *) buf, to_send);
        DEBUG_APPLE;

        if ( p->state == ARGO_STATE_CONNECTED )
        {
            DEBUG_APPLE;
            /* sponsor */
            ret = argo_stream_sendvto_from_sponsor(
                                  p, iovs, 2,
                                  to_send + sizeof(struct argo_stream_header),
                                  nonblock, &p->peer, ARGO_PROTO_STREAM);
            DEBUG_APPLE;
        }
        else
        {
            DEBUG_APPLE;
            /* private */
            ret = argo_stream_sendvto_from_private(
                                   p, iovs, 2,
                                   to_send + sizeof(struct argo_stream_header),
                                   nonblock, &p->peer, ARGO_PROTO_STREAM);
            DEBUG_APPLE;
        }

        if ( ret < 0 )
        {
            DEBUG_APPLE;
            return count ? count : ret;
        }

        len -= to_send;
        buf += to_send;
        count += to_send;

        if ( nonblock )
            return count;

        DEBUG_APPLE;
    }

    DEBUG_APPLE;
    DEBUG_APPLE;
#ifdef ARGO_DEBUG
    printk(KERN_ERR "avacado count=%d\n", count);
#endif
    return count;
}


static int
argo_bind(struct argo_private *p, struct argo_ring_id *ring_id)
{
    int ret = 0;

    DEBUG_APPLE;
    if ( ring_id->domain_id != XEN_ARGO_DOMID_ANY )
    {
        DEBUG_APPLE;

#ifdef ARGO_DEBUG
        printk(KERN_ERR "ring_id->domain(%x) != XEN_ARGO_DOMID_ANY(%x)",
               ring_id->domain_id, XEN_ARGO_DOMID_ANY);
#endif
        return -EINVAL;
    }

    DEBUG_APPLE;
#ifdef ARGO_DEBUG
    printk(KERN_ERR "argo_bind: %d (d: %d) (s: %d)\n", p->ptype,
           ARGO_PTYPE_DGRAM, ARGO_PTYPE_STREAM);
#endif

    switch (p->ptype)
    {
        case ARGO_PTYPE_DGRAM:
        {
            DEBUG_APPLE;
            ret = new_ring(p, ring_id);
            DEBUG_APPLE;
            if ( !ret )
                p->r->type = ARGO_RTYPE_DGRAM;
            DEBUG_APPLE;
            break;
        }
        case ARGO_PTYPE_STREAM:
        {
            DEBUG_APPLE;
            ret = new_ring(p, ring_id);
            DEBUG_APPLE;
            break;
        }
    }
    DEBUG_APPLE;
    return ret;
}

static int
argo_listen(struct argo_private *p)
{
    if ( (p->ptype != ARGO_PTYPE_STREAM) ||
         (p->state != ARGO_STATE_BOUND) )
        return -EINVAL;

    p->r->type = ARGO_RTYPE_LISTENER;
    p->state = ARGO_STATE_LISTENING;

    return 0;
}

/*
 * EC: Worst case scenario, see comment in argo_release.
 */
static void
#if ( LINUX_VERSION_CODE < KERNEL_VERSION(4,15,0) )
respite(unsigned long data)
{
    struct argo_private *p = (void *)data;
#else
respite(struct timer_list *t)
{
    struct argo_private *p = from_timer(p, t, to);
#endif

    p->pending_error = -ETIMEDOUT;
    p->state = ARGO_STATE_DISCONNECTED;
    wake_up_interruptible_all(&p->writeq);
}

static int
argo_connect(struct argo_private *p, xen_argo_addr_t *peer, int nonblock)
{
    struct argo_stream_header sh;
    int ret = -EINVAL;

    if ( p->ptype == ARGO_PTYPE_DGRAM )
    {
        switch (p->state)
        {
            case ARGO_STATE_BOUND:
            case ARGO_STATE_CONNECTED:
            {
                if (peer)
                {
                    p->state = ARGO_STATE_CONNECTED;
                    memcpy(&p->peer, peer, sizeof(xen_argo_addr_t));
                }
                else
                    p->state = ARGO_STATE_BOUND;
                return 0;
            }
            default:
                return -EINVAL;
        }
    }

    if ( p->ptype != ARGO_PTYPE_STREAM )
        return -EINVAL;

    if ( !peer )
        return -EFAULT;

    DEBUG_APPLE;

    /* Irritiatingly we need to be restartable */
    switch ( p->state )
    {
        case ARGO_STATE_BOUND:
        {
            p->r->type = ARGO_RTYPE_CONNECTOR;
            p->state = ARGO_STATE_CONNECTING;
            p->conid = argo_random32 ();
            p->peer = *peer;
            DEBUG_APPLE;

            sh.flags = ARGO_SHF_SYN;
            sh.conid = p->conid;
            DEBUG_APPLE;

            ret = xmit_queue_inline(&p->r->id, &p->peer, &sh, sizeof(sh),
                                    ARGO_PROTO_STREAM);

            if ( ret == sizeof(sh) )
                ret = 0;

            DEBUG_APPLE;
            if ( ret && (ret != -EAGAIN) )
            {
                DEBUG_APPLE;
                p->state = ARGO_STATE_BOUND;
                p->r->type = ARGO_RTYPE_DGRAM;
                return ret;
            }
            DEBUG_APPLE;
            break;
        }
        case ARGO_STATE_CONNECTED:
        {
            DEBUG_APPLE;
            if ( (peer->domain_id != p->peer.domain_id) ||
                 (peer->aport != p->peer.aport) )
            {
                DEBUG_BANANA;
                return -EINVAL;
            }
            else
                return 0;
        }
        case ARGO_STATE_CONNECTING:
        {
            if ( (peer->domain_id != p->peer.domain_id) ||
                 (peer->aport != p->peer.aport) )
            {
                DEBUG_BANANA;
                return -EINVAL;
            }
            DEBUG_APPLE;
            break;
        }
        default:
        {
            DEBUG_APPLE;
            return -EINVAL;
        }
    }

    DEBUG_APPLE;

    if ( nonblock )
      return -EINPROGRESS;

    DEBUG_APPLE;

#if ( LINUX_VERSION_CODE < KERNEL_VERSION(4,15,0) )
    init_timer(&p->to);
    p->to.function = &respite;
    p->to.data = (unsigned long) p;
#else
    timer_setup(&p->to, respite, 0);
#endif

    /* Default 5 seconds (in jiffies). A sysfs interface would be nice though. */
    mod_timer(&p->to, jiffies + msecs_to_jiffies(5000));          

    while (p->state != ARGO_STATE_CONNECTED)
    {
        DEBUG_APPLE;
        ret = wait_event_interruptible(p->writeq,
                                       (p->state != ARGO_STATE_CONNECTING));
        DEBUG_APPLE;
        if ( ret )
        {
            del_timer(&p->to);
            return ret;
        }
        DEBUG_APPLE;

        if (p->state == ARGO_STATE_DISCONNECTED)
        {
            DEBUG_APPLE;
            p->state = ARGO_STATE_BOUND;
            p->r->type = ARGO_RTYPE_DGRAM;
            ret = -ECONNREFUSED;
            break;
        }
        DEBUG_APPLE;
    }
    del_timer(&p->to);
    DEBUG_APPLE;

    return ret;
}

static char *
argofs_dname(struct dentry *dentry, char *buffer, int buflen)
{
    /* dynamic_dname is not exported */
    snprintf(buffer, buflen, "argo:[%lu]", dentry->d_inode->i_ino);
    return buffer;
}

static const struct dentry_operations argofs_dentry_operations = {
    .d_dname = argofs_dname,
};

static int
allocate_fd_with_private (void *private)
{
    int fd;
#if (LINUX_VERSION_CODE < KERNEL_VERSION(4,19,0))
    const struct qstr name = { .name = "" };
#else
    const char * name = "";
#endif
    struct file *f;
#if ( LINUX_VERSION_CODE < KERNEL_VERSION(4,19,0) )
    struct path path;
#endif
    struct inode *ind;

#if (LINUX_VERSION_CODE < KERNEL_VERSION(3,7,0))
    fd = get_unused_fd();
#else
    fd = get_unused_fd_flags(O_CLOEXEC);
#endif
    if ( fd < 0 )
        return fd;

#if ( LINUX_VERSION_CODE < KERNEL_VERSION(4,19,0) )
    path.dentry = d_alloc_pseudo(argo_mnt->mnt_sb, &name);
    if (unlikely(!path.dentry)) {
        put_unused_fd(fd);
          return -ENOMEM;
    }
#endif

    ind = new_inode(argo_mnt->mnt_sb);
    ind->i_ino = get_next_ino();
    ind->i_fop = argo_mnt->mnt_root->d_inode->i_fop;
    ind->i_state = argo_mnt->mnt_root->d_inode->i_state;
    ind->i_mode = argo_mnt->mnt_root->d_inode->i_mode;
    ind->i_uid = current_fsuid();
    ind->i_gid = current_fsgid();
#if ( LINUX_VERSION_CODE < KERNEL_VERSION(4,19,0) )
    d_instantiate(path.dentry, ind);
    path.mnt = mntget(argo_mnt);
#endif

    DEBUG_APPLE;
#if ( LINUX_VERSION_CODE < KERNEL_VERSION(4,19,0) )
    f = alloc_file(&path, FMODE_READ | FMODE_WRITE, &argo_fops_stream);
#else
    f = alloc_file_pseudo(ind, argo_mnt, name, O_RDWR, &argo_fops_stream);
#endif
    if ( !f )
    {
      //FIXME putback fd?
        return -ENFILE;
    }

    f->private_data = private;
#if ( LINUX_VERSION_CODE < KERNEL_VERSION(4,19,0) )
    f->f_flags = O_RDWR;
#endif
    fd_install (fd, f);

    return fd;
}

static int
argo_accept(struct argo_private *p, struct xen_argo_addr *peer, int nonblock)
{
    int fd;
    int ret = 0;
    struct argo_private *a = NULL;
    struct pending_recv *r;
    unsigned long flags;

    DEBUG_APPLE;

    if ( p->ptype != ARGO_PTYPE_STREAM )
        return -ENOTTY;

    if ( p->state != ARGO_STATE_LISTENING )
    {
        DEBUG_BANANA;
        return -EINVAL;
    }

//FIXME leak!

    DEBUG_APPLE;
    for (;;)
    {
        DEBUG_APPLE;

        ret = wait_event_interruptible(p->readq,
                                  (!list_empty (&p->pending_recv_list)) || nonblock);
        DEBUG_APPLE;

        if ( ret )
            return ret;
        DEBUG_APPLE;

        /*Write lock impliciity has pending_recv_lock */
        argo_write_lock_irqsave(&list_lock, flags); 

        DEBUG_APPLE;
        if ( !list_empty(&p->pending_recv_list) )
        {
            DEBUG_APPLE;

            r = list_first_entry(&p->pending_recv_list, struct pending_recv,
                                 node);
            DEBUG_APPLE;
            list_del(&r->node);
            DEBUG_APPLE;

            DEBUG_APPLE;
            atomic_dec(&p->pending_recv_count);
            DEBUG_APPLE;

            DEBUG_APPLE;
            if ( (!r->data_len) && (r->sh.flags & ARGO_SHF_SYN) )
                break;
            DEBUG_APPLE;

            argo_kfree(r);
        }
        DEBUG_APPLE;

        argo_write_unlock_irqrestore(&list_lock, flags);

        if ( nonblock )
            return -EAGAIN;
        DEBUG_APPLE;
    }
    DEBUG_APPLE;

    argo_write_unlock_irqrestore(&list_lock, flags);

    DEBUG_APPLE;

    do
    {
        DEBUG_APPLE;

        a = argo_kmalloc(sizeof(struct argo_private), GFP_KERNEL);

        if ( !a )
        {
            DEBUG_BANANA;
            ret = -ENOMEM;
            break;
        }
        DEBUG_APPLE;

        memset (a, 0, sizeof(struct argo_private));

        a->state = ARGO_STATE_ACCEPTED;
        a->ptype = ARGO_PTYPE_STREAM;
        a->r = p->r;

        if ( !get_ring (a->r) )
        {
            a->r = NULL;
            ret = -EINVAL;
            DEBUG_BANANA;
            break;
        }

        init_waitqueue_head(&a->readq);
        init_waitqueue_head(&a->writeq);
        argo_spin_lock_init(&a->pending_recv_lock);
        INIT_LIST_HEAD(&a->pending_recv_list);
        atomic_set(&a->pending_recv_count, 0);
        DEBUG_APPLE;

        a->send_blocked = 0;

        a->peer = r->from;
        a->conid = r->sh.conid;
        DEBUG_APPLE;

        if ( peer )
            *peer = r->from;

        fd = allocate_fd_with_private(a);
        if ( fd < 0 )
        {
            DEBUG_APPLE;
            ret = fd;
            break;
        }
        DEBUG_APPLE;

        argo_write_lock_irqsave(&list_lock, flags);
        list_add(&a->node, &a->r->privates);
        argo_write_unlock_irqrestore(&list_lock, flags);

/*Ship the ack -- */
        {
            struct argo_stream_header sh;

            DEBUG_APPLE;

            sh.conid = a->conid;
            sh.flags = ARGO_SHF_ACK;

            xmit_queue_inline(&a->r->id, &a->peer, &sh, sizeof(sh),
                              ARGO_PROTO_STREAM);

        }
#ifdef ARGO_DEBUG
        printk (KERN_ERR "argo_accept priv %p => %p\n", p, a);
#endif

        argo_kfree(r);

        /*
         * A new fd with a struct file having its struct file_operations in this
         * module is to be returned. The refcnt need to reflect that, so bump it.
         * Since that fd will eventualy be closed, the .release() callback will
         * decrement the refcnt.
         */
        try_module_get(THIS_MODULE);

        return fd;

    }
    while ( 0 );

    argo_kfree (r);

    DEBUG_APPLE;

    if ( a )
    {
        int need_ring_free = 0;

        argo_write_lock_irqsave(&list_lock, flags);

        if ( a->r )
            need_ring_free = put_ring(a->r);

        argo_write_unlock_irqrestore(&list_lock, flags);

        if ( need_ring_free )
            free_ring(a->r);

        argo_kfree(a);
        DEBUG_APPLE;
    }
    DEBUG_APPLE;

    return ret;
}

ssize_t
argo_sendto(struct argo_private * p, const void *buf, size_t len, int flags,
            xen_argo_addr_t * addr, int nonblock)
{
    ssize_t rc;

    if ( !access_ok_wrapper(VERIFY_READ, buf, len) )
        return -EFAULT;

#ifdef ARGO_DEBUG
    printk(KERN_ERR "argo_sendto buf:%p len:%d nonblock:%d\n", buf, len, nonblock);
#endif

    if ( flags & MSG_DONTWAIT )
        nonblock++;

    switch ( p->ptype )
    {
        case ARGO_PTYPE_DGRAM:
        {
            switch (p->state)
            {
                case ARGO_STATE_BOUND:
                    if ( !addr )
                        return -ENOTCONN;

                    rc = argo_sendto_from_sponsor(p, buf, len, nonblock, addr,
                                                  ARGO_PROTO_DGRAM);
                    break;

                case ARGO_STATE_CONNECTED:
                    if ( addr )
                        return -EISCONN;
#ifdef ARGO_DEBUG
                    printk (KERN_ERR
                      "KIWI trying send from connected udp socket to %d:%d from %d:%d\n",
                      (int) p->peer.domain_id, (int) p->peer.aport,
                      (int) p->r->id.domain_id,
                      (int) p->r->id.aport);
#endif

                    rc = argo_sendto_from_sponsor(p, buf, len, nonblock,
                                                  &p->peer, ARGO_PROTO_DGRAM);
                    break;

                default:
                    return -EINVAL;
            }
            break;
        }
        case ARGO_PTYPE_STREAM:
        {
            if ( addr )
                return -EISCONN;
            switch (p->state)
            {
                case ARGO_STATE_CONNECTING:
                case ARGO_STATE_BOUND:
                    return -ENOTCONN;
                case ARGO_STATE_CONNECTED:
                case ARGO_STATE_ACCEPTED:
                    rc = argo_send_stream(p, buf, len, nonblock);
                    break;
                case ARGO_STATE_DISCONNECTED:
                    DEBUG_BANANA;
                    rc = -EPIPE;
                    break;
                default:
                    DEBUG_BANANA;
                    return -EINVAL;
            }
            break;
        }
        default:
        {
            DEBUG_BANANA;
            return -ENOTTY;
        }
    }

    if ( (rc == -EPIPE) && !(flags & MSG_NOSIGNAL) )
        send_sig (SIGPIPE, current, 0);

    return rc;
}

ssize_t
argo_recvfrom(struct argo_private * p, void *buf, size_t len, int flags,
              xen_argo_addr_t * addr, int nonblock)
{
    int peek = 0;
    ssize_t rc = 0;

#ifdef ARGO_DEBUG
    printk(KERN_ERR "argo_recvfrom buff:%p len:%d nonblock:%d\n",
           buf, len, nonblock);
#endif
 
    if ( !access_ok_wrapper (VERIFY_WRITE, buf, len) )
        return -EFAULT;

    if ( flags & MSG_DONTWAIT )
        nonblock++;
    if ( flags & MSG_PEEK )
        peek++;

    switch ( p->ptype )
    {
        case ARGO_PTYPE_DGRAM:
        {
            rc = argo_recvfrom_dgram(p, buf, len, nonblock, peek, addr);
            break;
        }
        case ARGO_PTYPE_STREAM:
        {
            if (peek)
                return -EINVAL;
            DEBUG_APPLE;
            switch ( p->state )
            {
                case ARGO_STATE_BOUND:
                    return -ENOTCONN;
                case ARGO_STATE_CONNECTED:
                case ARGO_STATE_ACCEPTED:
                {
                    if (addr)
                        *addr = p->peer;
                    rc = argo_recv_stream (p, buf, len, flags, nonblock);
                    break;
                }
                case ARGO_STATE_DISCONNECTED:
                {
                    DEBUG_BANANA;
                    rc = 0;
                    break;
                }
                default:
                {
                    DEBUG_BANANA;
                    rc = -EINVAL;
                }
            }
        }
    }

    if ( (rc > (ssize_t)len) && !(flags & MSG_TRUNC) )
        rc = len;

    return rc;
}


/*****************************************fops ********************/

static int
argo_open_dgram(struct inode *inode, struct file *f)
{
    struct argo_private *p;

    p = argo_kmalloc(sizeof(struct argo_private), GFP_KERNEL);
    if ( !p )
        return -ENOMEM;

    memset(p, 0, sizeof(struct argo_private));
    p->state = ARGO_STATE_IDLE;
    p->desired_ring_size = DEFAULT_RING_SIZE;
    p->r = NULL;
    p->ptype = ARGO_PTYPE_DGRAM;
    p->send_blocked = 0;

    init_waitqueue_head(&p->readq);
    init_waitqueue_head(&p->writeq);

    argo_spin_lock_init(&p->pending_recv_lock);
    INIT_LIST_HEAD(&p->pending_recv_list);
    atomic_set(&p->pending_recv_count, 0);

#ifdef ARGO_DEBUG
    printk(KERN_ERR "argo_open priv %p\n", p);
#endif

    f->private_data = p;
    f->f_flags = O_RDWR;

    return 0;
}


static int
argo_open_stream(struct inode *inode, struct file *f)
{
    struct argo_private *p;

    p = argo_kmalloc(sizeof(struct argo_private), GFP_KERNEL);
    if ( !p )
        return -ENOMEM;

    memset(p, 0, sizeof(struct argo_private));
    p->state = ARGO_STATE_IDLE;
    p->desired_ring_size = DEFAULT_RING_SIZE;
    p->r = NULL;
    p->ptype = ARGO_PTYPE_STREAM;
    p->send_blocked = 0;

    init_waitqueue_head(&p->readq);
    init_waitqueue_head(&p->writeq);

    argo_spin_lock_init(&p->pending_recv_lock);
    INIT_LIST_HEAD(&p->pending_recv_list);
    atomic_set(&p->pending_recv_count, 0);

#ifdef ARGO_DEBUG
    printk(KERN_ERR "argo_open priv %p\n", p);
#endif

    f->private_data = p;
    f->f_flags = O_RDWR;

    return 0;
}


static int
argo_release(struct inode *inode, struct file *f)
{
    struct argo_private *p = (struct argo_private *) f->private_data;
    unsigned long flags;
    struct pending_recv *pending, *t;
    static volatile char tmp;
    int need_ring_free = 0;

    /* XC-8841 - make sure the ring info is properly mapped so we won't efault in xen
    * passing pointers to hypercalls.
    * Read the first and last byte, that should repage the structure */
    if ( p && p->r && p->r->ring )
        tmp = *((char*)p->r->ring) + *(((char*)p->r->ring)+sizeof(xen_argo_ring_t)-1);

    if ( p->ptype == ARGO_PTYPE_STREAM )
    {
        switch ( p->state )
        {
        /* EC: Assuming our process is killed while SYN is waiting in the ring 
         *     to be consumed (accept is yet to be scheduled).
         *     Connect will never wake up while the ring is destroy thereafter.
         *     We reply RST to every pending SYN in that situation.
         *     Still, the timeout handling on connect is required.
         *     If the connecting domain is scheduled by Xen while
         *     we're walking that list, it could possibly send another SYN by
         *     the time we're done (very unlikely though).
         *     This loop just speeds up the things in most cases.
         */
            case ARGO_STATE_LISTENING:
            {
                argo_spin_lock (&p->r->sponsor->pending_recv_lock);

                list_for_each_entry_safe(pending, t,
                                         &p->r->sponsor->pending_recv_list,
                                         node)
                {
                    if ( pending->sh.flags & ARGO_SHF_SYN )
                    {
                        /* Consume the SYN */
                        list_del(&pending->node);
                        atomic_dec(&p->r->sponsor->pending_recv_count);

                        xmit_queue_rst_to(&p->r->id, pending->sh.conid,
                                          &pending->from);
                        argo_kfree(pending);
                    }
                }
                argo_spin_unlock(&p->r->sponsor->pending_recv_lock);
                break;
            }
            case ARGO_STATE_CONNECTED:
            case ARGO_STATE_CONNECTING:
            case ARGO_STATE_ACCEPTED:
            {
                DEBUG_APPLE;
                xmit_queue_rst_to (&p->r->id, p->conid, &p->peer);
                break;
            }
            default:
                break;
        }
    }

    argo_write_lock_irqsave (&list_lock, flags);
    do
    {
        DEBUG_APPLE;
        if ( !p->r )
        {
            argo_write_unlock_irqrestore(&list_lock, flags);
            DEBUG_APPLE;
            break;
        }
        DEBUG_APPLE;

        if ( p != p->r->sponsor )
        {
            DEBUG_APPLE;

            need_ring_free = put_ring (p->r);
            list_del(&p->node);
            argo_write_unlock_irqrestore(&list_lock, flags);

            DEBUG_APPLE;
            break;
        }
        DEBUG_APPLE;

        //Send RST

        DEBUG_APPLE;
        p->r->sponsor = NULL;
        need_ring_free = put_ring(p->r);
        argo_write_unlock_irqrestore(&list_lock, flags);

        {
            struct pending_recv *pending;

            while (!list_empty (&p->pending_recv_list))
            {
                pending = list_first_entry(&p->pending_recv_list,
                                           struct pending_recv,
                                           node);

                list_del(&pending->node);
                argo_kfree(pending);
                atomic_dec(&p->pending_recv_count);
            }
        }
    }
    while ( 0 );

    if ( need_ring_free )
        free_ring(p->r);

    argo_kfree (p);

    return 0;
}

static ssize_t
argo_write(struct file *f,
           const char __user * buf, size_t count, loff_t * ppos)
{
    struct argo_private *p = f->private_data;
    int nonblock = f->f_flags & O_NONBLOCK;

    return argo_sendto(p, buf, count, 0, NULL, nonblock);
}

static ssize_t
argo_read(struct file *f, char __user * buf, size_t count, loff_t * ppos)
{
    struct argo_private *p = f->private_data;
    int nonblock = f->f_flags & O_NONBLOCK;

    return argo_recvfrom(p, (void *) buf, count, 0, NULL, nonblock);
}

static long
argo_ioctl(struct file *f, unsigned int cmd, unsigned long arg)
{
    // void __user *p = (void __user *) arg;
    // int len = _IOC_SIZE (cmd);
    int rc = -ENOTTY;

    int nonblock = f->f_flags & O_NONBLOCK;
    struct argo_private *p = f->private_data;

#ifdef ARGO_DEBUG
    printk (KERN_ERR "argo_ioctl cmd=%x pid=%d\n", cmd, current->pid);
#endif 
    if (_IOC_TYPE (cmd) != ARGO_TYPE)
        return rc;

    DEBUG_APPLE;
    switch (cmd)
    {
        case ARGOIOCSETRINGSIZE:
            DEBUG_APPLE;
            {
                uint32_t ring_size;
                if (get_user (ring_size, (uint32_t __user *)arg))
                    return -EFAULT;
                rc = argo_set_ring_size (p, ring_size);
            }
            break;
        case ARGOIOCBIND:
            DEBUG_APPLE;
            {
                struct argo_ring_id ring_id;
                if ( copy_from_user(&ring_id, (void __user *)arg,
                                    sizeof(struct argo_ring_id)) )
                    return -EFAULT;
                DEBUG_APPLE;
                rc = argo_bind (p, &ring_id);
            }
            break;
        case ARGOIOCGETSOCKNAME:
            if ( !access_ok_wrapper (VERIFY_WRITE, arg, sizeof(struct argo_ring_id)) )
                return -EFAULT;
            {
                struct argo_ring_id ring_id;
                argo_get_sock_name(p, &ring_id);
                if ( copy_to_user((void __user *)arg, &ring_id,
                                  sizeof(struct argo_ring_id)) )
                    return -EFAULT;
            }
            rc = 0;
            break;
        case ARGOIOCGETSOCKTYPE:
            DEBUG_APPLE;
            if ( !access_ok_wrapper (VERIFY_WRITE, arg, sizeof(int)) )
                return -EFAULT;
            {
                int sock_type;
                argo_get_sock_type(p, &sock_type);
                if ( put_user(sock_type, (int __user *)arg) )
                    return -EFAULT;
            }
            rc = 0;
            break;
        case ARGOIOCGETPEERNAME:
            DEBUG_APPLE;
            if ( !access_ok_wrapper (VERIFY_WRITE, arg, sizeof(xen_argo_addr_t)) )
                return -EFAULT;
            {
                xen_argo_addr_t addr;
                rc = argo_get_peer_name (p, &addr);
                if ( rc )
                    return rc;
                if ( copy_to_user((void __user *)arg, &addr,
                                  sizeof(xen_argo_addr_t)))
                    return -EFAULT;
            }
            break;
        case ARGOIOCCONNECT:
            DEBUG_APPLE;
            {
                xen_argo_addr_t connect_addr;
                if ( arg )
                {
                    if ( copy_from_user(&connect_addr, (void __user *)arg,
                                        sizeof(xen_argo_addr_t)) )
                        return -EFAULT;
                }

                //For for the lazy do a bind if it wasn't done
                if ( p->state == ARGO_STATE_IDLE )
                {
                    struct argo_ring_id id;
                    memset(&id, 0, sizeof(id));
                    id.partner_id = arg ? connect_addr.domain_id :
                                          XEN_ARGO_DOMID_ANY;
                    id.domain_id = XEN_ARGO_DOMID_ANY;
                    id.aport = 0;
                    rc = argo_bind(p, &id);
                    if ( rc )
                        break;
                }
                if ( arg )
                    rc = argo_connect(p, &connect_addr, nonblock);
                else
                    rc = argo_connect(p, NULL, nonblock);
            }
            break;
        case ARGOIOCGETCONNECTERR:
        {
            unsigned long flags;
            if ( !access_ok_wrapper(VERIFY_WRITE, arg, sizeof(int)) )
                return -EFAULT;
            DEBUG_APPLE;

            argo_spin_lock_irqsave (&p->pending_recv_lock, flags);
            if ( put_user (p->pending_error, (int __user *)arg) )
                rc = -EFAULT;
            else
            {
                p->pending_error = 0;
                rc = 0;
            }
            argo_spin_unlock_irqrestore (&p->pending_recv_lock, flags);
            DEBUG_APPLE;
        }
        break;
        case ARGOIOCLISTEN:
            DEBUG_APPLE;
            rc = argo_listen(p);
            break;
        case ARGOIOCACCEPT:
            DEBUG_APPLE;
            if ( !access_ok_wrapper(VERIFY_WRITE, arg, sizeof(xen_argo_addr_t)) )
                return -EFAULT;
            {
                xen_argo_addr_t addr;
                rc = argo_accept (p, &addr, nonblock);
                if ( rc < 0 )
                    return rc;
                if ( copy_to_user((void __user *)arg, &addr,
                                  sizeof(xen_argo_addr_t)) )
                    return -EFAULT;
            }
            break;
        case ARGOIOCSEND:
        {
            struct argo_dev a;
            xen_argo_addr_t addr;
            if ( copy_from_user(&a, (void __user *)arg,
                                sizeof(struct argo_dev)) )
                return -EFAULT;

            if ( a.addr)
            {
                if ( copy_from_user(&addr, (void __user *)a.addr,
                                    sizeof(xen_argo_addr_t)) )
                    return -EFAULT;
                DEBUG_APPLE;
                rc = argo_sendto(p, a.buf, a.len, a.flags, &addr, nonblock);
            }
            else
            {
                DEBUG_APPLE;
                rc = argo_sendto(p, a.buf, a.len, a.flags, NULL, nonblock);
            }
        }
        break;
        case ARGOIOCRECV:
        DEBUG_APPLE;
        {
            struct argo_dev a;
            xen_argo_addr_t addr;
            if ( copy_from_user(&a, (void __user *)arg, sizeof(struct argo_dev)) )
                return -EFAULT;
            if ( a.addr )
            {
                if ( copy_from_user (&addr, a.addr, sizeof(xen_argo_addr_t)) )
                    return -EFAULT;
                rc = argo_recvfrom (p, a.buf, a.len, a.flags, &addr, nonblock);
                if ( rc < 0 )
                    return rc;
                if ( copy_to_user (a.addr, &addr, sizeof(xen_argo_addr_t)) )
                    return -EFAULT;
            } else
                rc = argo_recvfrom (p, a.buf, a.len, a.flags, NULL, nonblock);
        }
        break;
        case ARGOIOCVIPTABLESADD:
        DEBUG_APPLE;
        {
            struct viptables_rule_pos rule_pos;
            struct xen_argo_viptables_rule rule;

            if ( copy_from_user(&rule_pos, (void __user *)arg,
                                sizeof(struct viptables_rule_pos)) ||
                 copy_from_user(&rule, rule_pos.rule,
                                sizeof(struct xen_argo_viptables_rule)) )
                return -EFAULT;

            rc = viptables_add(p, &rule, rule_pos.position);
        }
        break;
        case ARGOIOCVIPTABLESDEL:
        DEBUG_APPLE;
        {
            struct viptables_rule_pos rule_pos;
            struct xen_argo_viptables_rule rule;

            if ( copy_from_user(&rule_pos, (void __user *)arg,
                                sizeof(struct viptables_rule_pos)) )
                return -EFAULT;

            if ( rule_pos.rule )
            {
                if ( copy_from_user(&rule, rule_pos.rule,
                                    sizeof(struct xen_argo_viptables_rule)) )
                    return -EFAULT;

                rc = viptables_del(p, &rule, rule_pos.position);
            }
            else
                rc = viptables_del(p, NULL, rule_pos.position);
        }
        break;
        case ARGOIOCVIPTABLESLIST:
        DEBUG_APPLE;
        {
            struct xen_argo_viptables_list rules_list;

            if ( !access_ok_wrapper(VERIFY_WRITE, (void __user *)arg,
                            sizeof (struct xen_argo_viptables_list)) )
                return -EFAULT;

            if ( get_user(rules_list.nrules,
                          &((struct xen_argo_viptables_list *)arg)->nrules) )
                return -EFAULT;

            rc = viptables_list(p, &rules_list);
            if ( rc )
                return rc;

            if ( copy_to_user((void __user *)arg, &rules_list,
                              sizeof(struct xen_argo_viptables_list)) )
              return -EFAULT;
        }
        break;
        default:
            printk(KERN_ERR "unknown ioctl: cmd=%x ARGOIOCACCEPT=%lx\n", cmd,
                   ARGOIOCACCEPT);
            DEBUG_BANANA;
    }
    DEBUG_APPLE;
#ifdef ARGO_DEBUG
    printk (KERN_ERR "argo_ioctl cmd=%x pid=%d result=%d\n", cmd, current->pid, rc);
#endif
    return rc;
}

#ifdef CONFIG_COMPAT
static long
argo_compat_ioctl(struct file *f, unsigned int cmd, unsigned long arg)
{
    int nonblock = f->f_flags & O_NONBLOCK;
    struct argo_private *p = f->private_data;
    int rc;

    switch (cmd)
    {
        case ARGOIOCSEND32:
        {
            struct argo_dev a;
            struct argo_dev_32 a32;
            xen_argo_addr_t addr, *paddr = NULL;

            if ( copy_from_user(&a32, (void __user *)arg, sizeof(a32)) )
                return -EFAULT;

            a.buf = compat_ptr(a32.buf);
            a.len = a32.len;
            a.flags = a32.flags;
            a.addr = compat_ptr(a32.addr);

            if ( a.addr )
            {
                if ( copy_from_user(&addr, (void __user *)a.addr,
                                    sizeof(xen_argo_addr_t)) )
                    return -EFAULT;
                paddr = &addr;
                DEBUG_APPLE;
            }

            rc = argo_sendto (p, a.buf, a.len, a.flags, paddr, nonblock);
        }
        break;

        case ARGOIOCRECV32:
        DEBUG_APPLE;
        {
            struct argo_dev_32 a32;
            struct argo_dev a;
            xen_argo_addr_t addr;

            if ( copy_from_user(&a32, (void __user *)arg, sizeof(a32)) )
                return -EFAULT;

            a.buf = compat_ptr(a32.buf);
            a.len = a32.len;
            a.flags = a32.flags;
            a.addr = compat_ptr(a32.addr);

            if ( a.addr )
            {
                if ( copy_from_user (&addr, a.addr, sizeof(xen_argo_addr_t)) )
                    return -EFAULT;
                rc = argo_recvfrom(p, a.buf, a.len, a.flags, &addr, nonblock);
                if (rc < 0)
                    return rc;
                if (copy_to_user(a.addr, &addr, sizeof(xen_argo_addr_t)))
                    return -EFAULT;
            } else
                rc = argo_recvfrom(p, a.buf, a.len, a.flags, NULL, nonblock);
        }
        break;
        default:
            rc = argo_ioctl(f, cmd, (unsigned long)compat_ptr(arg));
    }

    return rc;
}
#endif

static unsigned int
argo_poll(struct file *f, poll_table * pt)
{
//FIXME
    unsigned int mask = 0;
    struct argo_private *p = f->private_data;
    argo_read_lock(&list_lock);

    switch (p->ptype)
    {
        case ARGO_PTYPE_DGRAM:
            switch (p->state)
            {
                case ARGO_STATE_CONNECTED:
                    //FIXME: maybe do something smart here
                case ARGO_STATE_BOUND:
                    poll_wait(f, &p->readq, pt);
                    mask |= POLLOUT | POLLWRNORM;
                    if ( p->r->ring->tx_ptr != p->r->ring->rx_ptr )
                        mask |= POLLIN | POLLRDNORM;
                    break;
                default:
                    break;
            }
            break;

        case ARGO_PTYPE_STREAM:
            switch (p->state)
            {
                case ARGO_STATE_BOUND:
                    break;
                case ARGO_STATE_LISTENING:
                    poll_wait(f, &p->readq, pt);
                    if (!list_empty(&p->pending_recv_list))
                        mask |= POLLIN | POLLRDNORM;
                    break;
                case ARGO_STATE_ACCEPTED:
                case ARGO_STATE_CONNECTED:
                    poll_wait(f, &p->readq, pt);
                    poll_wait(f, &p->writeq, pt);
                    if ( !p->send_blocked )
                        mask |= POLLOUT | POLLWRNORM;
                    if ( !list_empty(&p->pending_recv_list) )
                        mask |= POLLIN | POLLRDNORM;
                    break;
                case ARGO_STATE_CONNECTING:
                    poll_wait(f, &p->writeq, pt);
                    break;
                case ARGO_STATE_DISCONNECTED:
                    mask |= POLLOUT | POLLWRNORM;
                    mask |= POLLIN | POLLRDNORM;
                    break;
                case ARGO_STATE_IDLE:
                    break;
            }
            break;
    }

    argo_read_unlock(&list_lock);
    return mask;
}

static const struct file_operations argo_fops_stream = {
    .owner = THIS_MODULE,
    .write = argo_write,
    .read = argo_read,
    .unlocked_ioctl = argo_ioctl,
#ifdef CONFIG_COMPAT
    .compat_ioctl = argo_compat_ioctl,
#endif
    .open = argo_open_stream,
    .release = argo_release,
    .poll = argo_poll,
};


static const struct file_operations argo_fops_dgram = {
    .owner = THIS_MODULE,
    .write = argo_write,
    .read = argo_read,
    .unlocked_ioctl = argo_ioctl,
#ifdef CONFIG_COMPAT
    .compat_ioctl = argo_compat_ioctl,
#endif
    .open = argo_open_dgram,
    .release = argo_release,
    .poll = argo_poll,
};

/********************************xen virq goo ***************************/
static int argo_irq = -1;

#if 0
static struct irqaction argo_virq_action = {
  .handler = argo_interrupt,
  .flags = IRQF_SHARED,
  .name = "argo"
};
#endif

static void
unbind_signal_virq(void)
{
#if 0
    if (argo_irq >= 0)
        unbind_from_per_cpu_irq (argo_irq, 0, &argo_virq_action);
#else
    xc_unbind_from_irqhandler(argo_irq, NULL);
#endif
    argo_irq = -1;
}

static int
bind_signal_virq(void)
{
    int result;

#if 0
    result = bind_virq_to_irqaction(VIRQ_ARGO, 0, &argo_virq_action);
#else
    result = xc_bind_virq_to_irqhandler(VIRQ_ARGO, 0, argo_interrupt, 0,
                                        "argo", NULL);
#endif

    if ( result < 0 )
    {
        unbind_signal_virq();

#ifdef ARGO_DEBUG
        printk(KERN_ERR "Bind error %d\n", result);
#endif
        return result;
    }

    argo_irq = result;

    return 0;
}

/********************************xen signal goo *************************/
static void
unbind_signal(void)
{
    printk(KERN_ERR "argo unbind_signal: virq\n");
    unbind_signal_virq();
}

static int
bind_signal(void)
{
    int result;

    printk(KERN_ERR "argo: bind_signal: using virq\n");

    result = bind_signal_virq();

    return result;
}

/************************** argo device ****************************************/

static struct miscdevice argo_miscdev_dgram = {
    .minor = MISC_DYNAMIC_MINOR,
    .name = "argo_dgram",
    .fops = &argo_fops_dgram,
};

static struct miscdevice argo_miscdev_stream = {
    .minor = MISC_DYNAMIC_MINOR,
    .name = "argo_stream",
    .fops = &argo_fops_stream,
};

static int
argo_suspend(struct platform_device *dev, pm_message_t state)
{
    unbind_signal();
    return 0;
}

static int
argo_resume(struct platform_device *dev)
{
    struct ring *r;

    argo_read_lock(&list_lock);

    list_for_each_entry(r, &ring_list, node)
    {
        refresh_gfn_array(r);
        if ( register_ring(r) )
        {
            printk(KERN_ERR
                   "Failed to re-register a argo ring on resume, aport=0x%08x\n",
                    r->id.aport);
        }
    }

    argo_read_unlock(&list_lock);

    if ( bind_signal() )
    {
        printk(KERN_ERR "argo_resume: failed to bind argo signal\n");
        return -ENODEV;
    }
    return 0;
}

static void
argo_shutdown(struct platform_device *dev)
{
}

static int
#if (LINUX_VERSION_CODE < KERNEL_VERSION(3,8,0))
__devinit
#endif
argo_probe(struct platform_device *dev)
{
    int err = 0;
    int ret;

#ifdef ARGO_DEBUG
    printk(KERN_ERR "albatross: 1\n");
#endif

    ret = setup_fs ();
    if (ret)
        return ret;

    INIT_LIST_HEAD(&ring_list);
    rwlock_init(&list_lock);
    INIT_LIST_HEAD(&pending_xmit_list);
    argo_spin_lock_init(&pending_xmit_lock);
    argo_spin_lock_init(&interrupt_lock);
    atomic_set(&pending_xmit_count, 0);

    if ( bind_signal() )
    {
        printk(KERN_ERR "failed to bind argo signal\n");
        unsetup_fs ();
        return -ENODEV;
    }

    err = misc_register(&argo_miscdev_dgram);
    if ( err )
    {
        printk(KERN_ERR "Could not register /dev/argo_dgram\n");
        unsetup_fs();
        return err;
    }

    err = misc_register (&argo_miscdev_stream);
    if ( err )
    {
        printk(KERN_ERR "Could not register /dev/argo_stream\n");
        unsetup_fs();
        return err;
    }

    printk (KERN_INFO "Xen ARGO device installed.\n");
    return 0;
}

/*********** platform gunge *************/

static int
#if (LINUX_VERSION_CODE < KERNEL_VERSION(3,8,0))
__devexit
#endif
argo_remove(struct platform_device *dev)
{
    unbind_signal();
    misc_deregister(&argo_miscdev_dgram);
    misc_deregister(&argo_miscdev_stream);
    unsetup_fs();
    return 0;
}

static struct platform_driver argo_driver = {
    .driver = { .name = "argo",
                .owner = THIS_MODULE,
              },
    .probe = argo_probe,
#if (LINUX_VERSION_CODE >= KERNEL_VERSION(3,8,0))
    .remove = argo_remove,
#else
    .remove = __devexit_p(argo_remove),
#endif
    .shutdown = argo_shutdown,
    .suspend = argo_suspend,
    .resume = argo_resume,
};

static struct platform_device *argo_platform_device;

static int __init
argo_init(void)
{
    int error;

#ifdef XC_DKMS
    if ( !xen_hvm_domain() )
        return -ENODEV;
#else
#ifdef is_running_on_xen
    if ( !is_running_on_xen() )
        return -ENODEV;
#else
    if ( !xen_domain() )
        return -ENODEV;
#endif
#endif

    error = platform_driver_register(&argo_driver);
    if ( error )
        return error;

    argo_platform_device = platform_device_alloc("argo", -1);
    if ( !argo_platform_device )
    {
        platform_driver_unregister(&argo_driver);
        return -ENOMEM;
    }

    error = platform_device_add(argo_platform_device);
    if ( error )
    {
        platform_device_put(argo_platform_device);
        platform_driver_unregister(&argo_driver);
        return error;
    }
    return 0;
}

static void __exit
argo_cleanup(void)
{
  platform_device_unregister(argo_platform_device);
  platform_driver_unregister(&argo_driver);
}

module_init(argo_init);
module_exit(argo_cleanup);
MODULE_LICENSE ("GPL");
