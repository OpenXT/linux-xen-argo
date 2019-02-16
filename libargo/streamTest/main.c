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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "fileTransfer.h"

#define NUM_ARGS 8

int main(int argc, char **argv)
{
    int domid = 0;
    int port = 0;
    int parseOk = 0;
    int connect = 0;
    char *fileName = NULL;
    char *operation = NULL;
  
    printf("File test starting\n");

    //Work out what args we have.
    if (argc >= NUM_ARGS)
    {
        //Let's do the subsequent validation.
	if (!strcmp("-domid", argv[1]))
	{
	    domid = atoi(argv[2]);
	    parseOk = 1;
	    printf("Will accept from domain %d\n", domid);
	}
	
	if (parseOk)
	{
	    parseOk = 0;
	    if (!strcmp("-port", argv[3]))
	    {
		port = atoi(argv[4]);
		printf("Will listen/connect on port %d\n", port);
		parseOk = 1;
	    }
	}
	if (parseOk)
	{
	    parseOk = 0;
	    if (!strcmp("-file", argv[5]))
	    {
		fileName = argv[6];
		printf("Will use file %s\n", fileName);
		parseOk = 1;
	    }
	}
	if (parseOk)
	{
	    parseOk = 0;
	    if (!strcmp("-send", argv[7]))
	    {
                operation = OPERATION_SEND;
		parseOk = 1;
	    }
	    else if (!strcmp("-receive", argv[7]))
	    {
                operation = OPERATION_RECEIVE;
		parseOk = 1;
	    }
	    else if (!strncmp("-bounce", argv[7], OPERATION_BOUNCE_BASE_LENGTH))
	    {
                operation = &argv[7][1]; //Make sure to strip off the leading -
		parseOk = 1;
	    }
        }
        if (parseOk)
        {
            //This one is optional
	    if (argc > NUM_ARGS)
            {
	        if (!strcmp("-connect", argv[8]))
                    connect = 1;
            }
        }
    }

    //See if everything parsed ok.
    if (!parseOk)
    {
	printf("usage: %s -domid <domid> -port <portNum> -file <fileToTransfer> -send/receive/bounce_with_writev/bounce_with_one_write/bounce_with_many_writes [-connect]\n", argv[0]);
    }
    else
    {
	printf("Listening/connecting on port %d, and will %s the file %s\n", port, operation, fileName);

	//Let's do it.
	FileTransfer(domid, port, fileName, operation, connect);
    }
  
  return 0;
}
