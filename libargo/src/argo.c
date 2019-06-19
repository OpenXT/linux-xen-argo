/*
 * Copyright (c) 2012 Citrix Systems, Inc.
 * Modifications by Christopher Clark, Copyright (c) 2018 BAE Systems
 * 
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 * 
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 * 
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA
 */

#include "project.h"

#define I_AM_A_BROKEN_WEENIE

static size_t
count_iov (struct iovec *iov, int n)
{
  size_t ret = 0;

  while (n--)
    {
      ret += iov->iov_len;
      iov++;
    }
  return ret;
}


static void
unlinearize_iov (struct iovec *iov, int n, void *_buf)
{
  uint8_t *buf = (uint8_t *) _buf;

  while (n--)
    {
      memcpy (iov->iov_base, buf, iov->iov_len);
      buf += iov->iov_len;
      iov++;
    }
}


static void
linearize_iov (void *_buf, struct iovec *iov, int n)
{
  uint8_t *buf = (uint8_t *) _buf;

  while (n--)
  {
    memcpy(buf, iov->iov_base, iov->iov_len);
    buf += iov->iov_len;
    iov++;
  }
}


int
argo_socket (int type)
{
  int ret;
  int flags=type;

#ifdef SOCK_CLOEXEC
  type &= ~SOCK_CLOEXEC;
#endif

#ifdef SOCK_NONBLOCK
  type &= ~SOCK_NONBLOCK;
#endif

  switch (type)
    {
    case SOCK_STREAM:
      ret = open (ARGO_STREAM_DEV, O_RDWR);
      break;
    case SOCK_DGRAM:
      ret = open (ARGO_DGRAM_DEV, O_RDWR);
      break;
    default:
      errno = EPROTONOSUPPORT;
      return -1;
    }


#ifdef SOCK_CLOEXEC
    if (flags & SOCK_CLOEXEC) {
    long arg;
    arg = fcntl(ret, F_GETFD, arg);
    arg |= FD_CLOEXEC;
    if (fcntl(ret, F_SETFD, arg)) {
        close(ret);
        return -1;
    }
    }
#endif

#ifdef SOCK_NONBLOCK
    if (flags & SOCK_NONBLOCK) {
    long arg;
    arg = fcntl(ret, F_GETFL, arg);
    arg |= O_NONBLOCK;
    if (fcntl(ret, F_SETFL, arg)) {
        close(ret);
        return -1;
    }
    }
#endif

  return ret;
}

int
argo_close (int fd)
{
  return close (fd);
}



int
argo_bind (int fd, xen_argo_addr_t * addr, domid_t partner_id)
{
  struct argo_ring_id id;
  int ret;

  if (addr && !addr->domain_id)
      addr->domain_id = XEN_ARGO_DOMID_ANY;

  id.domain_id = addr->domain_id;
  id.aport = addr->aport;
  id.partner_id = partner_id;

  //no need for mlock, id is copied into kernel memory
  return argo_ioctl (fd, ARGOIOCBIND, &id);
}



int
argo_connect (int fd, xen_argo_addr_t * peer)
{
  //no need for mlock, peer is copied into kernel memory
  return argo_ioctl (fd, ARGOIOCCONNECT, peer);
}

int
argo_listen (int fd, int backlog)
{
  //no need for mlock
  return argo_ioctl (fd, ARGOIOCLISTEN, &backlog);
}

int
argo_accept (int fd, xen_argo_addr_t * peer)
{
  //no need for mlock, peer accessed from kernel
  return argo_ioctl (fd, ARGOIOCACCEPT, peer);
}



ssize_t
argo_send (int fd, const void *buf, size_t len, int flags)
{
  struct argo_dev op;
  ssize_t ret;

  op.buf = (void *) buf;
  op.len = len;
  op.flags = flags;
  op.addr = NULL;

#ifdef I_AM_A_BROKEN_WEENIE
  mlock (op.buf, op.len);
#endif

  ret = argo_ioctl (fd, ARGOIOCSEND, &op);

#ifdef I_AM_A_BROKEN_WEENIE
  munlock (op.buf, op.len);
#endif

  return ret;
}

ssize_t
argo_sendmsg (int fd, const struct msghdr * msg, int flags)
{
  struct argo_dev op;
  ssize_t ret;

  op.flags = flags;

  op.addr = (xen_argo_addr_t *) msg->msg_name;

  op.len = count_iov (msg->msg_iov, msg->msg_iovlen);
  op.buf = malloc (op.len);
  if (!op.buf)
    {
      errno = ENOMEM;
      return -1;
    }

  linearize_iov (op.buf, msg->msg_iov, msg->msg_iovlen);

#ifdef I_AM_A_BROKEN_WEENIE
  mlock (op.buf, op.len);
  if (op.addr)
    mlock (op.addr, sizeof (xen_argo_addr_t));
#endif

  //send is all in kernel
  ret = argo_ioctl (fd, ARGOIOCSEND, &op);

#ifdef I_AM_A_BROKEN_WEENIE
  if (op.addr)
    munlock (op.addr, sizeof (xen_argo_addr_t));
  munlock (op.buf, op.len);
#endif

  free (op.buf);

  return ret;
}

ssize_t
argo_sendto (int fd, const void *buf, size_t len, int flags,
            xen_argo_addr_t * dest_addr)
{
  struct argo_dev op;
  ssize_t ret;

  op.buf = (void *) buf;
  op.len = len;
  op.addr = dest_addr;
  op.flags = flags;

#ifdef I_AM_A_BROKEN_WEENIE
  mlock (op.buf, op.len);
  if (op.addr)
    mlock (op.addr, sizeof (xen_argo_addr_t));
#endif

  ret = argo_ioctl (fd, ARGOIOCSEND, &op);

#ifdef I_AM_A_BROKEN_WEENIE
  if (op.addr)
    munlock (op.addr, sizeof (xen_argo_addr_t));
  munlock (op.buf, op.len);
#endif

  return ret;
}


ssize_t
argo_recv (int fd, void *buf, size_t len, int flags)
{
  struct argo_dev op;
  ssize_t ret;

  op.addr = NULL;
  op.buf = buf;
  op.len = len;
  op.flags = flags;

  //recv is all in kernel
  ret = argo_ioctl (fd, ARGOIOCRECV, &op);

  return ret;
}

ssize_t
argo_recvmsg (int fd, struct msghdr * msg, int flags)
{
  struct argo_dev op;
  ssize_t ret;

  op.flags = flags;

  op.addr = (xen_argo_addr_t *) msg->msg_name;

  op.len = count_iov (msg->msg_iov, msg->msg_iovlen);
  op.buf = malloc (op.len);
  if (!op.buf)
    {
      errno = ENOMEM;
      return -1;
    }

  //recv is all in kernel
  ret = argo_ioctl (fd, ARGOIOCRECV, &op);

  unlinearize_iov (msg->msg_iov, msg->msg_iovlen, op.buf);
  free (op.buf);

  msg->msg_controllen = 0;

  return ret;
}


ssize_t
argo_recvfrom (int fd, void *buf, size_t len, int flags, xen_argo_addr_t * src_addr)
{
  struct argo_dev op;
  ssize_t ret;

  op.buf = buf;
  op.len = len;
  op.flags = flags;
  op.addr = src_addr;

  //recv is all in kernel
  return argo_ioctl (fd, ARGOIOCRECV, &op);
}


int
argo_getsockname (int fd, xen_argo_addr_t *out_addr, domid_t * out_partner_id)
{
  struct argo_ring_id id;
  int ret;

  //all in kernel
  ret = argo_ioctl (fd, ARGOIOCGETSOCKNAME, &id);

  if (out_partner_id)
    *out_partner_id = id.partner_id;

  if (out_addr)
  {
    out_addr->aport = id.aport;
    out_addr->domain_id = id.domain_id;
    out_addr->pad = 0;
  }

  return ret;
}


int
argo_getpeername (int fd, xen_argo_addr_t *out_addr)
{
  //all in kernel
  return argo_ioctl (fd, ARGOIOCGETPEERNAME, out_addr);
}

int
argo_getsockopt (int fd, int level, int optname,
                void *optval, socklen_t * optlen)
{
  int ret;

  if ((level == SOL_SOCKET) && (optname == SO_ERROR))
    {
      int error;

      //all in kernel
      ret = argo_ioctl (fd, ARGOIOCGETCONNECTERR, &error);
      if (ret)
        return ret;


      if (optval && optlen)
        {
          memcpy (optval, &error,
                  *optlen > sizeof (error) ? sizeof (error) : *optlen);
          *optlen = sizeof (error);
        }

      return 0;



    }
  if ((level == SOL_SOCKET) && (optname == SO_TYPE)) {
     int type;
     ret = argo_ioctl (fd, ARGOIOCGETSOCKTYPE, &type);
     if (ret)
         return ret;
     type = (type == ARGO_PTYPE_DGRAM) ? SOCK_DGRAM : SOCK_STREAM;
     if (optval && optlen) {
         memcpy(optval, &type, *optlen > sizeof (type) ? sizeof (type) : *optlen);
         *optlen = sizeof (type);
     }
     return 0;
   }
  errno = ENOPROTOOPT;
  return -1;
}

int
viptables_add (int fd, xen_argo_viptables_rule_t* rule, int position)
{
  int ret;
  struct viptables_rule_pos rule_pos;

  mlock (rule, sizeof(xen_argo_viptables_rule_t));
  rule_pos.rule = rule;
  rule_pos.position = position;

  ret = argo_ioctl (fd, ARGOIOCVIPTABLESADD, &rule_pos);

  munlock (rule, sizeof(xen_argo_viptables_rule_t));

  return ret;
}

int
viptables_del (int fd, xen_argo_viptables_rule_t* rule, int position)
{
  int ret;

  struct viptables_rule_pos rule_pos;

  if (rule != NULL)
    mlock (rule, sizeof(xen_argo_viptables_rule_t));

  rule_pos.rule = rule;
  rule_pos.position = position;

  ret = argo_ioctl (fd, ARGOIOCVIPTABLESDEL, &rule_pos);

  if (rule != NULL)
    munlock (rule, sizeof(xen_argo_viptables_rule_t));

  return ret;
}

int
viptables_flush (int fd)
{
  int ret;

  struct viptables_rule_pos rule_pos;

  rule_pos.rule = NULL;
  rule_pos.position = -1;

  ret = argo_ioctl (fd, ARGOIOCVIPTABLESDEL, &rule_pos);

  return ret;
}

static void
viptables_print_rule(struct xen_argo_viptables_rule *rule)
{
  if (rule->accept == 1)
    printf("ACCEPT");
  else
    printf("REJECT");

  printf(" ");

  if (rule->src.domain_id == DOMID_INVALID)
    printf("*");
  else
    printf("%i", rule->src.domain_id);

  printf(":");

  if (rule->src.aport == XEN_ARGO_PORT_ANY)
    printf("*");
  else
    printf("%i", rule->src.aport);

  printf(" -> ");

  if (rule->dst.domain_id == DOMID_INVALID)
    printf("*");
  else
    printf("%i", rule->dst.domain_id);

  printf(":");

  if (rule->dst.aport == XEN_ARGO_PORT_ANY)
    printf("*");
  else
    printf("%i", rule->dst.aport);

  printf("\n");
}

int
viptables_list (int fd)
{
  int ret, i, total_rules_printed = 0, rules_i = 1;

  struct xen_argo_viptables_list rules_list;
  memset(&rules_list, 0, sizeof (rules_list));

  do
  {
      rules_list.nrules = total_rules_printed;
      ret = argo_ioctl (fd, ARGOIOCVIPTABLESLIST, &rules_list);

      if (ret != 0)
          return ret;

      for (i = 0; i < rules_list.nrules; ++i)
      {
          printf("%i : ", rules_i++);
          viptables_print_rule(&rules_list.rules[i]);
      }

      total_rules_printed += rules_list.nrules;

  } while (rules_list.nrules == XEN_ARGO_VIPTABLES_LIST_SIZE);

  return ret;
}
