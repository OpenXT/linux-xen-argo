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

#include <stdlib.h>
#include <stdio.h>
#include <getopt.h>
#include "libv4v.h"

enum action_e
{
  NONE,
  APPEND,
  INSERT,
  LIST,
  DELETE,
  FLUSH
};

void usage(int exit_value)
{
  fprintf(stderr, "Usage: viptables command [rule]\n");
  fprintf(stderr, "Commands :\n");
  fprintf(stderr, "  --append	-A			Append rule\n");
  fprintf(stderr, "  --insert	-I <n>			Insert rule before rule <n>\n");
  fprintf(stderr, "  --list	-L			List rules\n");
  fprintf(stderr, "  --delete	-D[<n>]			Delete rule <n> or the following rule\n");
  fprintf(stderr, "  --flush	-F			Flush rules\n");
  fprintf(stderr, "  --help	-h			Help\n");
  fprintf(stderr, "Rule options:\n");
  fprintf(stderr, "  --dom-in	-d <n>			Client domid\n");
  fprintf(stderr, "  --dom-out	-e <n>			Server domid\n");
  fprintf(stderr, "  --port-in	-p <n>			Client port\n");
  fprintf(stderr, "  --port-out	-q <n>			Server port\n");
  fprintf(stderr, "  --jump	-j {ACCEPT|REJECT}	What to do\n");

  exit(exit_value);
}

int main (int argc, char** argv)
{
  int c;
  int fd;
  int rc = -1;

  v4v_viptables_rule_t rule;
  int position = -1;
  enum action_e action = NONE;

  rule.src.domain = DOMID_INVALID;
  rule.src.port = -1;
  rule.dst.domain = DOMID_INVALID;
  rule.dst.port = -1;
  rule.accept = -1;

  static struct option long_options[] =
    {
      {"append",   no_argument,       0, 'A'},
      {"insert",   required_argument, 0, 'I'},
      {"list",     no_argument,       0, 'L'},
      {"delete",   optional_argument, 0, 'D'},
      {"flush",    no_argument,       0, 'F'},

      {"dom-in",   required_argument, 0, 'd'},
      {"dom-out",  required_argument, 0, 'e'},
      {"port-in",  required_argument, 0, 'p'},
      {"port-out", required_argument, 0, 'q'},

      {"jump",     required_argument, 0, 'j'},

      {"help",     no_argument,       0, 'h'},
      {0, 0, 0, 0}
    };

  int option_index = 0;

  c = getopt_long (argc, argv, "AI:LD::Fd:e:p:q:j:h",
		   long_options, &option_index);

  if (c == -1)
    usage(1);

  while (c >= 0)
    {
      switch (c)
	{
	case 'A':
	  action = APPEND;
	  break;
	case 'I':
	  action = INSERT;
	  position = atoi(optarg);
	  break;
	case 'L':
	  action = LIST;
	  break;
	case 'D':
	  action = DELETE;
	  if (optarg != NULL && *optarg != '\0')
	    position = atoi(optarg);
	  break;
	case 'F':
	  action = FLUSH;
	  break;
	case 'd':
	  rule.src.domain = atoi(optarg);
	  break;
	case 'e':
	  rule.dst.domain = atoi(optarg);
	  break;
	case 'p':
	  rule.src.port = atoi(optarg);
	  break;
	case 'q':
	  rule.dst.port = atoi(optarg);
	  break;
	case 'j':
	  if (!strcmp(optarg, "ACCEPT"))
	    rule.accept = 1;
	  else if (!strcmp(optarg, "REJECT"))
	    rule.accept = 0;
	  else
	    usage(1);
	  break;
	case 'h':
	  usage(0);
	  break;
	default:
	  usage(1);
	}

      c = getopt_long (argc, argv, "AI:LD:d:e:p:q:j:h",
		   long_options, &option_index);
    }

  fd = v4v_socket(SOCK_STREAM);
  if (fd < 0)
    {
      perror("v4v_socket");
      exit(1);
    }

  switch (action)
    {
    case APPEND:
      if (rule.accept == -1)
	usage(1);
      rc = v4v_viptables_add(fd, &rule, -1);
      break;
    case INSERT:
      if (rule.accept == -1)
	usage(1);
      rc = v4v_viptables_add(fd, &rule, position);
      break;
    case LIST:
      rc = v4v_viptables_list(fd);
      break;
    case DELETE:
      if (position != -1)
        rc = v4v_viptables_del(fd, NULL, position);
      else
        rc = v4v_viptables_del(fd, &rule, -1);
      break;
    case FLUSH:
      rc = v4v_viptables_flush(fd);
      break;
    default:
      usage(1);
    }

  v4v_close(fd);

  return rc;
}
