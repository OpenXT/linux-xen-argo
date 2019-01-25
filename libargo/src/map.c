/*
 * Copyright (c) 2010 Citrix Systems, Inc.
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


static uint32_t
map_port (uint16_t sin_port)
{
  return (uint32_t) sin_port;
}

static uint16_t
unmap_port (uint32_t argo_port)
{
  return (uint16_t) argo_port;
}


void
argo_map_argoa_to_sin (struct sockaddr *addr, socklen_t * addrlen,
                     xen_argo_addr_t * peer)
{
  struct sockaddr_in sin;

  memset (&sin, 0, sizeof (sin));

  sin.sin_family = AF_INET;
  sin.sin_port = unmap_port (htons (peer->aport));

  if (peer->domain_id == XEN_ARGO_DOMID_ANY)
    {
      sin.sin_addr.s_addr = INADDR_ANY;
    }
  else
    {
      sin.sin_addr.s_addr = htonl ((uint32_t) peer->domain_id | 0x1000000);
    }


  if (addr && addrlen)
    memcpy (addr, &sin, (*addrlen < sizeof (sin)) ? *addrlen : sizeof (sin));

  if (addrlen)
    *addrlen = sizeof (sin);
}


int
argo_map_sin_to_argoa (xen_argo_addr_t * peer, const struct sockaddr *addr,
                     int addrlen)
{
  const struct sockaddr_in *sin = (const struct sockaddr_in *) addr;

  if (addrlen != sizeof (struct sockaddr_in))
    return -EINVAL;

  if (sin->sin_family != AF_INET)
    return -EINVAL;

  if (sin->sin_addr.s_addr == INADDR_ANY)
    {
      peer->domain_id = XEN_ARGO_DOMID_ANY;
    }
  else
    {
      peer->domain_id = ntohl (sin->sin_addr.s_addr) & 0xffff;
    }

  peer->aport = map_port (ntohs (sin->sin_port));

  return 0;
}

void
argo_map_argoa_to_sxenargo (struct sockaddr *addr, socklen_t * addrlen,
                         xen_argo_addr_t * peer)
{
  struct sockaddr_xenargo sxenargo;

  memset (&sxenargo, 0, sizeof (sxenargo));

  sxenargo.sxenargo_family = AF_XENARGO;
  sxenargo.sxenargo_port = peer->aport;
  sxenargo.sxenargo_domain = peer->domain_id;

  if (addr && addrlen)
    memcpy (addr, &sxenargo,
            (*addrlen < sizeof (sxenargo)) ? *addrlen : sizeof (sxenargo));

  if (addrlen)
    *addrlen = sizeof (sxenargo);
}

int
argo_map_sxenargo_to_argoa (xen_argo_addr_t * peer,
                         const struct sockaddr *addr, int addrlen)
{
  const struct sockaddr_xenargo *sxenargo =
    (const struct sockaddr_xenargo *) addr;

  if (addrlen != sizeof (struct sockaddr_xenargo))
    return -EINVAL;

  if (addrlen != sizeof (struct sockaddr_xenargo))
    return -EINVAL;

  if (sxenargo->sxenargo_family != AF_XENARGO)
    return -EINVAL;

  peer->domain_id = sxenargo->sxenargo_domain;
  peer->aport = sxenargo->sxenargo_port;

  return 0;
}

int
argo_map_sa_to_argoa (xen_argo_addr_t * peer,
                    const struct sockaddr *addr, int addrlen)
{
  switch (addr->sa_family)
    {
    case AF_XENARGO:
      return argo_map_sxenargo_to_argoa (peer, addr, addrlen);
    case AF_INET:
      return argo_map_sin_to_argoa (peer, addr, addrlen);
    }
  return -EINVAL;
}
