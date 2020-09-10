/*
 * Copyright (c) 2012 Citrix Systems, Inc.
 * Modifications by Christopher Clark are Copyright (c) 2018 BAE Systems
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

#ifndef __ARGO_DEV_H__
#define __ARGO_DEV_H__

#include <linux/argo.h>

typedef enum
{
  ARGO_PTYPE_DGRAM = 1,
  ARGO_PTYPE_STREAM,
} argo_ptype;

/* The pointers make this depend on compilation. */
struct argo_dev {
	void *buf;
	size_t len;
	int flags;
	xen_argo_addr_t *addr;
};

/* A 64bit version of argo_dev */
struct argo_dev_64 {
	uint64_t buf;
	size_t len;
	int flags;
	uint64_t addr;
};

/* A 32bit version of argo_dev used for compat ioctls */
struct argo_dev_32 {
	uint32_t buf;
	uint32_t len;
	int32_t flags;
	uint32_t addr;
};

struct argo_ring_id {
	domid_t domain_id;
	domid_t partner_id;
	xen_argo_port_t aport;
};

struct viptables_rule_pos {
    struct xen_argo_viptables_rule* rule;
    int position;
};

#define ARGO_TYPE 'W'

#define ARGOIOCSETRINGSIZE 	_IOW (ARGO_TYPE,  1, uint32_t)
#define ARGOIOCBIND		_IOW (ARGO_TYPE,  2, struct argo_ring_id)
#define ARGOIOCGETSOCKNAME	_IOW (ARGO_TYPE,  3, struct argo_ring_id)
#define ARGOIOCGETPEERNAME	_IOW (ARGO_TYPE,  4, xen_argo_addr_t)
#define ARGOIOCCONNECT		_IOW (ARGO_TYPE,  5, xen_argo_addr_t)
#define ARGOIOCGETCONNECTERR	_IOW (ARGO_TYPE,  6, int)
#define ARGOIOCLISTEN		_IOW (ARGO_TYPE,  7, uint32_t) /*unused args */
#define ARGOIOCACCEPT		_IOW (ARGO_TYPE,  8, xen_argo_addr_t)
#define ARGOIOCSEND		_IOW (ARGO_TYPE,  9, struct argo_dev)
#define ARGOIOCRECV		_IOW (ARGO_TYPE, 10, struct argo_dev)
/* ARGOIOCSEND32==ARGOIOCSEND for 32bit kernels, but not for compat 64bit */
#define ARGOIOCSEND32		_IOW (ARGO_TYPE,  9, struct argo_dev_32)
#define ARGOIOCRECV32		_IOW (ARGO_TYPE, 10, struct argo_dev_32)
#define ARGOIOCGETSOCKTYPE	_IOW (ARGO_TYPE, 11, int)
#define ARGOIOCVIPTABLESADD  _IOW (ARGO_TYPE, 12, struct viptables_rule_pos)
#define ARGOIOCVIPTABLESDEL  _IOW (ARGO_TYPE, 13, struct viptables_rule_pos)
#define ARGOIOCVIPTABLESLIST _IOW (ARGO_TYPE, 14, uint32_t) /*unused args */

#endif
