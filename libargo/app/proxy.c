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

#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <fcntl.h>
#include <string.h>
#include <errno.h>
#include <signal.h>


#include <sys/types.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <netinet/in.h>

#include <sys/select.h>

#include "libv4v.h"

static void
sigchld_handler (int dummy)
{
  int status;
  waitpid (-1, &status, WNOHANG);
}

static void
shotgun (void)                  /*Anti zombie medicine */
{
  struct sigaction act = { 0 };

  act.sa_handler = sigchld_handler;

  sigaction (SIGCHLD, &act, NULL);
}

static void
die (char *msg)
{
  perror (msg);
  exit (1);
}

static void
usage ()
{
  printf ("Usage:\nv4v-proxy [-p port] [-p port2] ...\n");
  exit (1);
}

void
set_nonblock (int fd)
{
  long arg;
  arg = fcntl (fd, F_GETFL, arg);
  arg |= O_NONBLOCK;
  fcntl (fd, F_SETFL, arg);
}

int
complete_write (int fd, void *_buf, int len)
{
  char *buf = _buf;
  int writ;
  fd_set fds;
  struct timeval tv;

  memset (&tv, 0, sizeof (tv));

  FD_ZERO (&fds);
  FD_SET (fd, &fds);

  while (len)
    {

      tv.tv_sec = 1;
      tv.tv_usec = 0;

      select (fd + 1, NULL, &fds, NULL, &tv);

      writ = write (fd, buf, len);

      switch (writ)
        {
        case -1:
          if (errno == EAGAIN || errno == EINTR)
            break;

          return -1;
        case 0:
          exit (0);
        default:
          buf += writ;
          len -= writ;

        }
    }

  return 0;
}

static void
proxy (int afd, int port)
{
  int xfd;
  struct sockaddr_xenv4v sxl, sxr;
  int n, red;
  fd_set fds;
  char buf[1024];

  xfd = socket (PF_XENV4V, SOCK_STREAM, 0);
  if (!xfd)
    die ("socket(PF_XENV4V,SOCK_STREAM,0);");

  memset (&sxl, 0, sizeof (sxl));

  sxl.sxenv4v_family = AF_XENV4V;
  sxl.sxenv4v_port = 0;
  sxl.sxenv4v_domain = V4V_DOMID_NONE;

  if (bind (xfd, (struct sockaddr *) &sxl, sizeof (sxl)))
    die ("bind(xen_socket,....);");


  memset (&sxr, 0, sizeof (sxr));


  sxr.sxenv4v_family = AF_XENV4V;
  sxr.sxenv4v_port = port;
  sxr.sxenv4v_domain = 0;

  if (connect (xfd, (struct sockaddr *) &sxr, sizeof (sxr)))
    die ("connext(xen_socket,....);");

  n = xfd > afd ? xfd : afd;
  n++;

  set_nonblock (afd);
  set_nonblock (xfd);

  FD_ZERO (&fds);

  do
    {

      if (FD_ISSET (afd, &fds))
        {
          red = read (afd, buf, sizeof (buf));

          switch (red)
            {
            case -1:
              if (errno == EAGAIN)
                break;
              die ("read(inet_socket,.......);");
            case 0:
              exit (0);
            default:
              if (complete_write (xfd, buf, red))
                die ("write(xen_socket,.....);");
            }
        }

      if (FD_ISSET (xfd, &fds))
        {
          red = read (xfd, buf, sizeof (buf));
          switch (red)
            {
            case -1:
              if (errno == EAGAIN)
                break;
              die ("read(inet_socket,.......);");
            case 0:
              exit (0);
            default:
              if (complete_write (afd, buf, red))
                die ("write(xen_socket,.....);");
            }
        }

      FD_SET (afd, &fds);
      FD_SET (xfd, &fds);

    }
  while (select (n, &fds, NULL, NULL, NULL) >= 0);
  exit (1);
}

int
main (int argc, char *argv[])
{
  struct sockaddr_in sin;

  int sfd, afd;
  int one = 1;

  int nports=0, ports[256];
  pid_t chs[256];
  int opt;
  int p,i;

  shotgun();

  while ((opt = getopt (argc, argv, "p:")) != -1)
    {
      switch (opt)
        {
        case 'p':
          if (!optarg)
            usage ();
          p = atoi (optarg);
          if (!p)
            usage ();
          ports[nports++] = p;
          break;
        default:
          usage ();
        }
    }

  if (!nports) {
      nports = 1;
      ports[0] = 80;
  }

  for (i=0; i<nports; ++i) {
      int port = ports[i];
      memset (&sin, 0, sizeof (sin));
      pid_t ch = fork();
      if (ch) {
          printf("listening on %d, pid=%d\n", ports[i], ch);
          chs[i] = ch;
      } else {
          sfd = socket (PF_INET, SOCK_STREAM, 0);
          if (!sfd)
              die ("socket(PF_INET,SOCK_STREAM,0);");
      
          if (setsockopt (sfd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof one))
              die
                  ("setsockopt(inet_socket, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));");

          sin.sin_family = AF_INET;
          sin.sin_addr.s_addr = INADDR_ANY;
          sin.sin_port = htons (port);
      
          if (bind (sfd, (struct sockaddr *) &sin, sizeof (sin)))
              die ("bind(inet_socket,....);");
      
      
          listen (sfd, 5);

          while (afd = accept (sfd, NULL, NULL))
          {
              if (afd < 0) {
                  if (errno == EINTR)
                      continue;
                  die ("accept(inet_socket,......);");
              }
              
              switch (fork ())
              {
              case 0:
                  close (sfd);
                  proxy (afd, port);
                  break;
              case -1:
                  die ("fork();");
              default:
                  break;
              }
              close (afd);
          }
      }
  }
  for (i=0; i<nports; ++i) {
      int st;
      waitpid(chs[i], &st, 0);
  }
}
