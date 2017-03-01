/*
 * Copyright (c) 2010 Citrix Systems, Inc.
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


static uint32_t
map_port (uint16_t sin_port)
{
  return (uint32_t) sin_port;
}

static uint16_t
unmap_port (uint32_t v4v_port)
{
  return (uint16_t) v4v_port;
}


void
v4v_map_v4va_to_sin (struct sockaddr *addr, socklen_t * addrlen,
                     v4v_addr_t * peer)
{
  struct sockaddr_in sin;

  memset (&sin, 0, sizeof (sin));

  sin.sin_family = AF_INET;
  sin.sin_port = unmap_port (htons (peer->port));

  if (peer->domain == V4V_DOMID_NONE)
    {
      sin.sin_addr.s_addr = INADDR_ANY;
    }
  else
    {
      sin.sin_addr.s_addr = htonl ((uint32_t) peer->domain | 0x1000000);
    }


  if (addr && addrlen)
    memcpy (addr, &sin, (*addrlen < sizeof (sin)) ? *addrlen : sizeof (sin));

  if (addrlen)
    *addrlen = sizeof (sin);
}


int
v4v_map_sin_to_v4va (v4v_addr_t * peer, const struct sockaddr *addr,
                     int addrlen)
{
  const struct sockaddr_in *sin = (const struct sockaddr_in *) addr;

  if (addrlen != sizeof (struct sockaddr_in))
    return -EINVAL;

  if (sin->sin_family != AF_INET)
    return -EINVAL;

  if (sin->sin_addr.s_addr == INADDR_ANY)
    {
      peer->domain = V4V_DOMID_NONE;
    }
  else
    {
      peer->domain = ntohl (sin->sin_addr.s_addr) & 0xffff;
    }

  peer->port = map_port (ntohs (sin->sin_port));

  return 0;
}

void
v4v_map_v4va_to_sxenv4v (struct sockaddr *addr, socklen_t * addrlen,
                         v4v_addr_t * peer)
{
  struct sockaddr_xenv4v sxenv4v;

  memset (&sxenv4v, 0, sizeof (sxenv4v));

  sxenv4v.sxenv4v_family = AF_XENV4V;
  sxenv4v.sxenv4v_port = peer->port;
  sxenv4v.sxenv4v_domain = peer->domain;

  if (addr && addrlen)
    memcpy (addr, &sxenv4v,
            (*addrlen < sizeof (sxenv4v)) ? *addrlen : sizeof (sxenv4v));

  if (addrlen)
    *addrlen = sizeof (sxenv4v);
}

int
v4v_map_sxenv4v_to_v4va (v4v_addr_t * peer,
                         const struct sockaddr *addr, int addrlen)
{
  const struct sockaddr_xenv4v *sxenv4v =
    (const struct sockaddr_xenv4v *) addr;

  if (addrlen != sizeof (struct sockaddr_xenv4v))
    return -EINVAL;

  if (addrlen != sizeof (struct sockaddr_xenv4v))
    return -EINVAL;

  if (sxenv4v->sxenv4v_family != AF_XENV4V)
    return -EINVAL;

  peer->domain = sxenv4v->sxenv4v_domain;
  peer->port = sxenv4v->sxenv4v_port;

  return 0;
}

int
v4v_map_sa_to_v4va (v4v_addr_t * peer,
                    const struct sockaddr *addr, int addrlen)
{
  switch (addr->sa_family)
    {
    case AF_XENV4V:
      return v4v_map_sxenv4v_to_v4va (peer, addr, addrlen);
    case AF_INET:
      return v4v_map_sin_to_v4va (peer, addr, addrlen);
    }
  return -EINVAL;
}
