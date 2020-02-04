/******************************************************************************
 * Argo : Hypervisor-Mediated data eXchange
 *
 * Copyright (c) 2020, BAE Systems
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to
 * deal in the Software without restriction, including without limitation the
 * rights to use, copy, modify, merge, publish, distribute, sublicense, and/or
 * sell copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
 * FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER
 * DEALINGS IN THE SOFTWARE.
 *
 */
#ifndef __XEN_LINUX_ARGO_H__
#define __XEN_LINUX_ARGO_H__

/*
 * Both DOMID_INVALID and domid_t are defined in the Linux xen.h interface
 * header file, which unfortunately is not part of the standard libc headers,
 * so it would need to be obtained from the Linux kernel headers.
 * There is practical benefit to avoiding introducing a dependency on the Linux
 * kernel headers - which are MACHINE-specific in the OpenEmbedded build -
 * because it causes unnecessary package rebuilds in multi-MACHINE systems such
 * as OpenXT, when in fact these are are MACHINE-agnostic definitions; so:
 * just define these two needed items here if they are not already available.
 */
#ifndef DOMID_INVALID
typedef uint16_t domid_t;
#define DOMID_INVALID (0x7FF4U)
#endif

/*
 * Items below here are the subset of those defined in the public Xen Argo
 * header, or the OpenXT viptables additions to it, that are exposed by the
 * Linux kernel driver to Linux userspace.
 * Only supply these definitions if that hypervisor header has not already
 * been included.
 * This enables substitution of this header (<linux/argo.h>) for the public
 * hypervisor one (<xen/argo.h>) for Linux userspace use, and so avoid a
 * dependency on the availability of the hypervisor headers.
 */
#ifndef __XEN_PUBLIC_ARGO_H__

#define XEN_ARGO_DOMID_ANY DOMID_INVALID

#define XEN_ARGO_PORT_ANY  0xFFFFFFFFU
#define XEN_ARGO_PORT_NONE 0

/* Fixed-width type for "argo port" number. Nothing to do with evtchns. */
typedef uint32_t xen_argo_port_t;

typedef struct xen_argo_addr
{
    xen_argo_port_t aport;
    domid_t domain_id;
    uint16_t pad;
} xen_argo_addr_t;

typedef struct xen_argo_viptables_rule
{
    struct xen_argo_addr src;
    struct xen_argo_addr dst;
    uint32_t accept;
} xen_argo_viptables_rule_t;

#define XEN_ARGO_VIPTABLES_LIST_SIZE 8

typedef struct xen_argo_viptables_list
{
    struct xen_argo_viptables_rule rules[XEN_ARGO_VIPTABLES_LIST_SIZE];
    uint32_t nrules;
} xen_argo_viptables_list_t;

#endif
#endif
