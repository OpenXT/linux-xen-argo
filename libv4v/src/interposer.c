/*
 * Copyright (c) 2012 Citrix Systems, Inc.
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

#define INTERPOSE(n,rt,p...)  \
		static rt (*orig_ ## n) (p); \
		INTERNAL rt n (p)

#define CHECK_INTERPOSE(n) \
		do { \
			init(); \
			if (!orig_ ## n) { \
				errno=ENOSYS; \
				return -1; \
			} \
		} while (1==0)

#define FIND(n) do { orig_ ## n=dlsym(RTLD_NEXT, #n ); } while (1==0)

static void init (void);

/*
 * v4v_fds:     lists interposed fd's
 * v4v_checked: lists fd's we have already checked are not V4V
 * v4v_afs:     lists fd's with AF_XENV4V
 */
static fd_set v4v_fds;
static fd_set v4v_checked;
static fd_set v4v_afs;

static int force_xen;

static void inline
do_register (fd_set * p, int fd)
{
  if ((fd<0) || (fd>=FD_SETSIZE)) return;
  FD_SET (fd, p);
}


static void inline
do_unregister (fd_set * p, int fd)
{
  if ((fd<0) || (fd>=FD_SETSIZE)) return;
  FD_CLR (fd, p);
}

static int inline
is_registered (fd_set * p, int fd)
{
  if ((fd<0) || (fd>=FD_SETSIZE)) return 0;
  return FD_ISSET (fd, p);
}


static void inline
register_fd (int fd)
{
  do_register (&v4v_fds, fd);
}

static void inline
unregister_fd (int fd)
{
  do_unregister (&v4v_fds, fd);
}


static void
check_fd (int fd)
{
#if 0
  /* This would be a better way if the accept()'ed socket
   * had the /dev/v4v_* inode but for now it doesn't */
  struct stat st;
  if (v4v_dgram_inode.st_ino == (ino_t) (-1L) ||
      v4v_stream_inode.st_ino == (ino_t) (-1L))
    {
      if (stat (V4V_DGRAM_DEV, &st))
        return;
      v4v_dgram_inode.st_dev = st.st_dev;
      v4v_dgram_inode.st_ino = st.st_ino;
      if (stat (V4V_STREAM_DEV, &st))
        return;
      v4v_stream_inode.st_dev = st.st_dev;
      v4v_stream_inode.st_ino = st.st_ino;
    }
  if (fstat (fd, &st))
    return;
  do_register (&v4v_checked, fd);
  if (((st.st_dev == v4v_stream_inode.st_dev) &&
       (st.st_ino == v4v_stream_inode.st_ino)) ||
      ((st.st_dev == v4v_dgram_inode.st_dev) &&
       (st.st_ino == v4v_dgram_inode.st_ino)))
    do_register (&v4v_fds, fd);
#else
  struct v4v_ring_id id;
  int ret;

  do_register (&v4v_checked, fd);
  if (!ioctl (fd, V4VIOCGETSOCKNAME, &id))
    {
      do_register (&v4v_fds, fd);
    }
#endif
}


static int inline
is_our_fd (int fd)
{
  if ((!is_registered (&v4v_fds, fd)) && (!is_registered (&v4v_checked, fd)))
    {
      check_fd (fd);
    }
  return is_registered (&v4v_fds, fd);
}


static void inline
register_af (int fd)
{
  do_register (&v4v_afs, fd);
}

static void inline
unregister_af (int fd)
{
  do_unregister (&v4v_afs, fd);
}

static int inline
is_our_af (int fd)
{
  return is_registered (&v4v_afs, fd);
}

static void
do_copy (fd_set * p, int src, int dst)
{
  if ((src<0) || (src>=FD_SETSIZE)) return;
  if ((dst<0) || (dst>=FD_SETSIZE)) return;
  if (FD_ISSET (src, p))
    FD_SET (dst, p);
  else
    FD_CLR (dst, p);
}

static void
copy_our_fd (int src, int dst)
{
  do_copy (&v4v_fds, src, dst);
}

static void
copy_our_af (int src, int dst)
{
  do_copy (&v4v_afs, src, dst);
}

static void init (void);


INTERPOSE (socket, int, int domain, int type, int protocol)
{
  int ret;

  CHECK_INTERPOSE (socket);

  if ((domain != PF_XENV4V) && (domain != PF_INETV4V) &&
      ((domain != PF_INET) || (!getenv ("INET_IS_V4V"))) && !force_xen)
    return orig_socket (domain, type, protocol);

  ret = v4v_socket (type);
  if (ret < 0)
    return ret;

  register_fd (ret);

  if (domain == PF_XENV4V)
    register_af (ret);
  else
    unregister_af (ret);

  return ret;
}

INTERPOSE (close, int, int fd)
{
  CHECK_INTERPOSE (close);

  unregister_fd (fd);

  return orig_close (fd);
}


INTERPOSE (bind, int, int sockfd, const struct sockaddr * addr,
           socklen_t addrlen)
{
  v4v_addr_t v4va;

  CHECK_INTERPOSE (bind);

  if (!is_our_fd (sockfd))
    return orig_bind (sockfd, addr, addrlen);

  if (addr->sa_family == AF_XENV4V)
    register_af (sockfd);
  else
    unregister_af (sockfd);

  if (v4v_map_sa_to_v4va (&v4va, addr, addrlen))
    return -EINVAL;

  return v4v_bind (sockfd, &v4va,
                   getenv ("V4V_ACCEPT_DOM0_ONLY") ? 0 : V4V_DOMID_NONE);
}



INTERPOSE (connect, int, int sockfd, const struct sockaddr * addr,
           socklen_t addrlen)
{
  v4v_addr_t peer, me;
  char *val, *end;
  int addend, ret;

  CHECK_INTERPOSE (connect);

  if (!is_our_fd (sockfd))
    return orig_connect (sockfd, addr, addrlen);

  if (v4v_map_sa_to_v4va (&peer, addr, addrlen))
    return -EINVAL;

  /* Bind the socket to a specific port if requested */
  val = getenv ("V4V_CLIENT_PORT_ADDEND");
  if (val != NULL) {
    addend = strtol(val, &end, 10);
    /* Sanitize the addend */
    if (end == NULL || *end != '\0' || addend < 0)
      return -EINVAL;
    me.domain = V4V_DOMID_ANY;
    me.port = peer.port + addend;
    DEBUG_PRINTF ("BINDING CLIENT TO port %d\n", (int) me.port);
    DEBUG_PRINTF ("  AND SET %d AS THE PARTNER\n", (int) peer.domain);
    ret = v4v_bind(sockfd, &me, peer.domain);
    if (ret)
      return ret;
  }

  DEBUG_PRINTF ("CONNECTING TO %d:%d\n", (int) peer.domain, (int) peer.port);

  return v4v_connect (sockfd, &peer);
}

INTERPOSE (listen, int, int sockfd, int backlog)
{
  int ret;

  CHECK_INTERPOSE (listen);

  if (!is_our_fd (sockfd))
    return orig_listen (sockfd, backlog);

  return v4v_listen (sockfd, backlog);
}

INTERPOSE (accept, int, int sockfd, struct sockaddr * addr,
           socklen_t * addrlen)
{
  v4v_addr_t peer;
  int ret;

  CHECK_INTERPOSE (accept);

  if (!is_our_fd (sockfd))
    return orig_accept (sockfd, addr, addrlen);

  ret = v4v_accept (sockfd, &peer);

  register_fd (ret);

  if (is_our_af (sockfd))
    {
      v4v_map_v4va_to_sxenv4v (addr, addrlen, &peer);
    }
  else
    {
      v4v_map_v4va_to_sin (addr, addrlen, &peer);
    }

  return ret;
}



INTERPOSE (send, ssize_t, int sockfd, const void *buf, size_t len, int flags)
{
  CHECK_INTERPOSE (send);

  if (!is_our_fd (sockfd))
    return orig_send (sockfd, buf, len, flags);


  return v4v_send (sockfd, buf, len, flags);
}

INTERPOSE (sendmsg, ssize_t, int sockfd, const struct msghdr * msg, int flags)
{
  struct msghdr v4vmsg;
  v4v_addr_t v4va;
  CHECK_INTERPOSE (sendmsg);

  if (!is_our_fd (sockfd))
    return orig_sendmsg (sockfd, msg, flags);

  if (!msg)
	  return -EINVAL;

  v4vmsg = *msg;
  if (v4vmsg.msg_name) {
	if (v4v_map_sa_to_v4va(&v4va, v4vmsg.msg_name, v4vmsg.msg_namelen))
		return -EINVAL;
	v4vmsg.msg_name = &v4va;
	v4vmsg.msg_namelen = sizeof(v4va);
  }

  return v4v_sendmsg (sockfd, &v4vmsg, flags);
}

INTERPOSE (sendto, ssize_t, int sockfd, const void *buf, size_t len,
           int flags, const struct sockaddr * dest_addr, socklen_t addrlen)
{
  v4v_addr_t peer;

  CHECK_INTERPOSE (sendto);

  if (!is_our_fd (sockfd))
    return orig_sendto (sockfd, buf, len, flags, dest_addr, addrlen);

  if (dest_addr && v4v_map_sa_to_v4va (&peer, dest_addr, addrlen))
    return -EINVAL;

  return v4v_sendto (sockfd, buf, len, flags, dest_addr ? &peer : NULL);

}


INTERPOSE (recv, ssize_t, int sockfd, void *buf, size_t len, int flags)
{
  CHECK_INTERPOSE (recv);

  if (!is_our_fd (sockfd))
    return orig_recv (sockfd, buf, len, flags);

  return v4v_recv (sockfd, buf, len, flags);
}

INTERPOSE (recvmsg, ssize_t, int sockfd, struct msghdr * msg, int flags)
{
  struct v4v_addr peer;
  struct msghdr my_msg = *msg;
  ssize_t ret;

  CHECK_INTERPOSE (recvmsg);

  if (!is_our_fd (sockfd))
    return orig_recvmsg (sockfd, msg, flags);

  if (msg->msg_name)
    {
      my_msg.msg_name = &peer;
    }


  ret = v4v_recvmsg (sockfd, &my_msg, flags);


  if (msg->msg_name)
    {
      if (is_our_af (sockfd))
        {
          v4v_map_v4va_to_sxenv4v (msg->msg_name, &msg->msg_namelen, &peer);
        }
      else
        {
          v4v_map_v4va_to_sin (msg->msg_name, &msg->msg_namelen, &peer);
        }
    }

  msg->msg_controllen = my_msg.msg_controllen;

  return ret;
}


INTERPOSE (recvfrom, ssize_t, int sockfd, void *buf, size_t len,
           int flags, struct sockaddr * src_addr, socklen_t * addrlen)
{
  ssize_t ret;
  v4v_addr_t peer = { 0 };

  CHECK_INTERPOSE (recvfrom);

  if (!is_our_fd (sockfd))
    return orig_recvfrom (sockfd, buf, len, flags, src_addr, addrlen);

  ret = v4v_recvfrom (sockfd, buf, len, flags, &peer);

  if (is_our_af (sockfd))
    {
      v4v_map_v4va_to_sxenv4v (src_addr, addrlen, &peer);
    }
  else
    {
      v4v_map_v4va_to_sin (src_addr, addrlen, &peer);
    }

  return ret;
}


INTERPOSE (getsockname, int, int sockfd, struct sockaddr * addr,
           socklen_t * addrlen)
{
  ssize_t ret;
  v4v_addr_t name;

  CHECK_INTERPOSE (getsockname);

  if (!is_our_fd (sockfd))
    return orig_getsockname (sockfd, addr, addrlen);

  ret = v4v_getsockname (sockfd, &name, NULL);

  if (is_our_af (sockfd))
    {
      v4v_map_v4va_to_sxenv4v (addr, addrlen, &name);
    }
  else
    {
      v4v_map_v4va_to_sin (addr, addrlen, &name);
    }

  return ret;
}


INTERPOSE (getpeername, int, int sockfd, struct sockaddr * addr,
           socklen_t * addrlen)
{
  ssize_t ret;
  v4v_addr_t ring_addr = { 0 };

  CHECK_INTERPOSE (getpeername);

  if (!is_our_fd (sockfd))
    return orig_getpeername (sockfd, addr, addrlen);

  ret = v4v_getpeername (sockfd, &ring_addr);

  if (is_our_af (sockfd))
    {
      v4v_map_v4va_to_sxenv4v (addr, addrlen, &ring_addr);
    }
  else
    {
      v4v_map_v4va_to_sin (addr, addrlen, &ring_addr);
    }

  return ret;
}

INTERPOSE (dup, int, int oldfd)
{
  int ret;
  CHECK_INTERPOSE (dup);

  ret = orig_dup (oldfd);

  copy_our_fd (oldfd, ret);
  copy_our_af (oldfd, ret);

  return ret;
}


INTERPOSE (dup2, int, int oldfd, int newfd)
{
  int ret;

  CHECK_INTERPOSE (dup2);

  ret = orig_dup2 (oldfd, newfd);

  copy_our_fd (oldfd, ret);
  copy_our_af (oldfd, ret);


  return ret;
}

INTERPOSE (dup3, int, int oldfd, int newfd, int flags)
{
  int ret;

  CHECK_INTERPOSE (dup3);

  ret = dup3 (oldfd, newfd, flags);

  copy_our_fd (oldfd, ret);
  copy_our_af (oldfd, ret);


  return ret;
}


INTERPOSE (shutdown, int, int sockfd, int how)
{
  CHECK_INTERPOSE (shutdown);

  if (!is_our_fd (sockfd))
    return orig_shutdown (sockfd, how);

  return 0;
}

INTERPOSE (setsockopt, int, int sockfd, int level, int optname,
           const void *optval, socklen_t optlen)
{
  CHECK_INTERPOSE (setsockopt);

  if (!is_our_fd (sockfd))
    return orig_setsockopt (sockfd, level, optname, optval, optlen);

  if ((level == SOL_SOCKET) && (optname == SO_KEEPALIVE))
    {
      /* Can be safely ignored */
      return 0;
    }
  if ((level == SOL_SOCKET) && (optname == SO_REUSEADDR))
    {
      //FIXME
      return 0;
    }
  if ((level == SOL_SOCKET) && (optname == SO_LINGER))
    {
      //FIXME
      return 0;
    }

  if ((level == IPPROTO_IP) && (optname == IP_PKTINFO))
    {
      //FIXME
      return 0;
    }
  if ((level == IPPROTO_IP) && (optname == IP_TOS))
    {
      /* Can be safely ignored */
      return 0;
    }
  if ((level == IPPROTO_IP) && (optname == IP_TTL))
    {
      /* Can be safely ignored */
      return 0;
    }

  if ((level == IPPROTO_TCP) && (optname == TCP_NODELAY))
    {
      //FIXME
      return 0;
    }


  DEBUG_PRINTF ("unknown setsockopt %d %d %d %p %d\n",
                sockfd, level, optname, optval, optlen);

  errno = ENOPROTOOPT;
  return -1;
}


INTERPOSE (getsockopt, int, int sockfd, int level, int optname,
           void *optval, socklen_t * optlen)
{
  int ret;
  CHECK_INTERPOSE (getsockopt);

  if (!is_our_fd (sockfd))
    return orig_getsockopt (sockfd, level, optname, optval, optlen);

  return v4v_getsockopt (sockfd, level, optname, optval, optlen);
}



static void
init (void)
{
  static int ready;

  if (ready)
    return;

  FD_ZERO (&v4v_fds);
  FD_ZERO (&v4v_afs);

#if 0
  v4v_dgram_inode.st_dev = (dev_t) (-1L);
  v4v_dgram_inode.st_ino = (ino_t) (-1L);
#endif

  FIND (socket);
  FIND (close);
  FIND (bind);
  FIND (connect);
  FIND (accept);
  FIND (listen);
  FIND (send);
  FIND (sendmsg);
  FIND (sendto);
  FIND (recv);
  FIND (recvmsg);
  FIND (recvfrom);
  FIND (dup);
  FIND (dup2);
  FIND (dup3);
  FIND (setsockopt);
  FIND (getsockopt);
  FIND (getsockname);
  FIND (getpeername);
  FIND (shutdown);

  ready++;
}
