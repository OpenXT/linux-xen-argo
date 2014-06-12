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
#include <string.h>
#include <stdlib.h>
#include <stdbool.h>
#include <libv4v.h>
#include <sys/socket.h>
#include <sys/select.h>
#include <sys/uio.h>
#include "fileTransfer.h"



int TransferSizeTable[] = {12, 14, 17, 32,64, 128, 243, 512, 1024, 2048, 4096, 8192, 16384, 32758, 65535};

int GetBiggestBufferSize(void)
{
    int returnValue = 0;
    int numEntries = sizeof(TransferSizeTable) / sizeof(int);
    int i = 0;

    for (i = 0; i < numEntries; i++)
    {
	if (TransferSizeTable[i] > returnValue)
	{
	    returnValue = TransferSizeTable[i];
	}
    }

    printf("Biggest buffer size is %d\n", returnValue);
    return returnValue;
    
}

int WaitForIncomingConnection(int listenPort, int domid)
{
    int keepGoing = 1;
    int returnValue = 0;
    int svrSocket = 0;
    v4v_addr_t addr;
    v4v_addr_t peer;
    printf("%s begin.\n", __FUNCTION__);

    svrSocket = v4v_socket (SOCK_STREAM);
    if (svrSocket < 0)
    {
	printf("domid %d: socket(PF_XENV4V,SOCK_STREAM,0) failed: %m\n", domid);
    }
    else
    {
	addr.domain = V4V_DOMID_ANY;
	addr.port = listenPort;

	/*We need the special v4v version of this call to bind for one domain only*/
	if (v4v_bind (svrSocket, &addr, domid))
	{
	    printf("domid %d: v4v_bind(fd,SOCK_STREAM,0) failed: %m\n", domid);
	}

	if (v4v_listen (svrSocket, 5))
	{
	    printf ("domid %d: listen(fd,SOCK_STREAM,0) failed: %m\n", domid);
	}
	else
	{
	    keepGoing = 1;
	}

	if (keepGoing)
	{
	    printf("All listening ok, waiting to accept\n");
	    returnValue = v4v_accept(svrSocket, &peer);

	    printf("Accept returned %d\n", returnValue);
	}

	close(svrSocket);
    }

    printf("%s end. return %d\n", __FUNCTION__, returnValue);
    return returnValue;
}

void CloseConnection(int connection)
{
    close(connection);
}

void ReceiveFile(int connection, char *fileName)
{
    char *readBuffer = NULL;
    ssize_t readBufferSize = 0;
    ssize_t bytesRead = 0;
    ssize_t bytesWritten = 0;
    FILE *fileDescriptor = 0;
    int keepGoing = 1;
    int totalBytesReceived = 0;
    int totalBytesToFile = 0;

    //Work out the buffer.
    readBufferSize = GetBiggestBufferSize();
    readBuffer = malloc(readBufferSize);

    //Open up the file.
    fileDescriptor = fopen(fileName, "w");

    if ((fileDescriptor != NULL) && (readBuffer != NULL))
    {
	printf("Will save to %s\n", fileName);

	while (keepGoing)
	{
	    bytesRead = read(connection, readBuffer, readBufferSize);  
	    
	    if (bytesRead <= 0)
	    {
		printf("read from v4v returned %d, so exiting\n", bytesRead);
		keepGoing = 0;
	    }
	    else
	    {
		totalBytesReceived += bytesRead;
		bytesWritten = fwrite(readBuffer, 1, bytesRead, fileDescriptor);
		totalBytesToFile += bytesWritten;
		fflush(fileDescriptor);
		printf("read from v4v returned %d bytes. totalBytesReceived %d, totalBytesToFile %d.\n", 
		       bytesRead, 
		       totalBytesReceived,
		       totalBytesToFile);
	    }
	}

	free(readBuffer);
	fclose(fileDescriptor);
	printf("total bytes received %d\n", totalBytesReceived);
    }
    else
    {
	printf("cannot create %s\n", fileName);
    }


}

void SendFile(int connection, char *fileName)
{
    char *writeBuffer = NULL;
    ssize_t writeBufferSize = 0;
    ssize_t bytesRead = 0;
    ssize_t bytesWritten = 0;
    FILE *fileDescriptor = 0;
    int keepGoing = 1;
    int totalBytesRead = 0;
    int totalBytesToSocket = 0;
    int currentSizeIndex = 0;
    int currentIteration = 0;
    int currentSize = 0;
    int numTableEntries = sizeof(TransferSizeTable) / sizeof(int);

    //Work out the buffer.
    writeBufferSize = GetBiggestBufferSize();
    writeBuffer = malloc(writeBufferSize);

    //Open up the file.
    fileDescriptor = fopen(fileName, "r");

    if ((fileDescriptor != NULL) && (writeBuffer != NULL))
    {
	printf("Will read from %s\n", fileName);
	
	while (keepGoing) 
	{
    	    currentSizeIndex = currentIteration % numTableEntries;
    	    currentSize = TransferSizeTable[currentSizeIndex];

            bytesRead = fread(writeBuffer, 1, currentSize, fileDescriptor);  
	    if (bytesRead <= 0)
	    {
		printf("read from file returned %d, so exiting\n", bytesRead);
		keepGoing = 0;
	    }
	    else
	    {
		totalBytesRead += bytesRead;
		bytesWritten = write(connection, writeBuffer, bytesRead);
		totalBytesToSocket += bytesWritten;
		fflush(fileDescriptor);
		printf("read from file returned %d bytes. totalBytesRead %d, totalBytesToSocket %d.\n", 
		       bytesRead, 
		       totalBytesRead,
		       totalBytesToSocket);
	    }
	    currentIteration++;
	}

	free(writeBuffer);
	fclose(fileDescriptor);
	printf("total bytes to socket %d\n", totalBytesToSocket);
    }
    else
    {
	printf("cannot open %s\n", fileName);
    }


}


void BounceData(int context, BounceType bounceType)
{


    //What we do is receive data from the other side and send it back.
    //Each packet will have the following format:
    //size:seqNum:data
    //DWORD:DWORD:variableSize
    struct iovec writeVec[3]; 
    char *readBuffer = NULL;
    char *writeBuffer = NULL;
    char *currentPtr = NULL;
    ssize_t readBufferSize = 0;
    ssize_t writeBufferSize = 0;
    ssize_t bytesRead = 0;
    ssize_t bytesWritten = 0;
    ssize_t bytesWrittenThisPacket = 0;
    int keepGoing = 1;
    int totalBytesReceived = 0;
    int totalBytesSent = 0;
    unsigned int sequenceNumber = 0;
    unsigned int packetSize = 0;
    unsigned int bytesToRead = 0;
    int i = 0;

    printf("%s begin.\n", __FUNCTION__);

    //Work out the buffer.
    readBufferSize = GetBiggestBufferSize();
    readBuffer = malloc(readBufferSize);
    writeBufferSize = readBufferSize;
    writeBuffer = malloc(writeBufferSize);

    if (readBuffer != NULL)
    {
	printf("sanity things. sizeof(unsigned int) %d, sizeof(int) %d\n", sizeof(unsigned int), sizeof(int));
	while (keepGoing)
	{
	    
	    //Get the packet size.
	    bytesRead = read(context, &packetSize, sizeof(unsigned int));
	    if (bytesRead <= 0)
	    {
		printf("reading packet size returned %d, so exiting\n", bytesRead);
		keepGoing = 0;
		break;
	    }
	    totalBytesReceived += bytesRead;

	    //Get the sequence.
	    bytesRead = read(context, &sequenceNumber, sizeof(unsigned int));
	    if (bytesRead <= 0)
	    {
		printf("reading sequence number  returned %d, so exiting\n", bytesRead);
		keepGoing = 0;
		break;
	    }
	    totalBytesReceived += bytesRead;

//	    printf("%s got packet 0x%08x, size 0x%08x\n", __FUNCTION__, sequenceNumber, packetSize);

	    //Get the data.
	    bytesToRead = packetSize - (sizeof(unsigned int) * 2);
	    bytesRead = read(context, readBuffer, bytesToRead);  
	    
	    if (bytesRead <= 0)
	    {
		printf("reading data returned %d, so exiting\n", bytesRead);
		keepGoing = 0;
		break;
	    }

	    //OK, we've got a full packet.Let's send it back. As it is spread across a few pieces of data,
	    //we could consider doing a gathering write.
	    totalBytesReceived += bytesRead;
	    printf("%s fully received packet 0x%08x, size 0x%08x. totalBytesReceived %d\n",
		   __FUNCTION__,
		   sequenceNumber,
		   packetSize,
		   totalBytesReceived);

	    //Now send it back. How we send it varies based on the kind of writing to do.

	    if (bounceType == eWriteV)
	    {
		writeVec[0].iov_base = &packetSize;
		writeVec[0].iov_len = sizeof(unsigned int);
		writeVec[1].iov_base = &sequenceNumber;
		writeVec[1].iov_len = sizeof(unsigned int);
		writeVec[2].iov_base = readBuffer;
		writeVec[2].iov_len = bytesRead;
		bytesWritten = writev(context, writeVec, 3);
		//printf("writev returned %d\n", bytesWritten);
	    }
	    else if (bounceType == eManyWrites)
	    {
		bytesWrittenThisPacket = 0;
		bytesWritten = write(context, &packetSize, sizeof(unsigned int));
		if (bytesWritten <= 0)
		{
		    printf("writing packetSize returned %d, so exiting\n", bytesWritten);
		    keepGoing = 0;
		    break;
		}
		bytesWrittenThisPacket += bytesWritten;

		bytesWritten = write(context, &sequenceNumber, sizeof(unsigned int));
		if (bytesWritten <= 0)
		{
		    printf("writing sequenceNumber returned %d, so exiting\n", bytesWritten);
		    keepGoing = 0;
		    break;
		}
		bytesWrittenThisPacket += bytesWritten;

		bytesWritten = write(context, readBuffer, bytesRead);
		if (bytesWritten <= 0)
		{
		    printf("writing packetData returned %d, so exiting\n", bytesWritten);
		    keepGoing = 0;
		    break;
		}

		bytesWrittenThisPacket += bytesWritten;
		if (bytesWrittenThisPacket != packetSize)
		{
		    printf("%s problem doing sequence of small writes. Wrote %d, expected %d.\n",
			   __FUNCTION__,
			   bytesWrittenThisPacket,
			   packetSize);
		    keepGoing = 0;
		    break;
  
		}

		//Update the bytesWritten to reflect the whole packet, as every other approach uses
		//this one.
		bytesWritten = bytesWrittenThisPacket;
	    }
	    else if (bounceType == eOneWrite)
	    {
		currentPtr = writeBuffer;
		memcpy(currentPtr, &packetSize, sizeof(unsigned int));
		currentPtr += sizeof(unsigned int);
		memcpy(currentPtr, &sequenceNumber, sizeof(unsigned int));
		currentPtr += sizeof(unsigned int);
		memcpy(currentPtr, readBuffer, bytesRead);
		printf("%s buffer to write is:\n", __FUNCTION__);
		for (i = 0; i < packetSize; i++)
		{
		    printf("0x%02x,", (unsigned char) writeBuffer[i]);
		}
		printf("\n");
		bytesWritten = write(context, writeBuffer, packetSize);
	    }
	    else
	    {
		printf("%s invalid bounce type of %d given. Cannot continue\n", __FUNCTION__, bounceType);
		keepGoing = false;
		break;
	    }

	    if (bytesWritten <= 0)
	    {
		printf("writing data returned %d, so exiting\n", bytesWritten);
		keepGoing = 0;
		break;
	    }
	    totalBytesSent += bytesWritten;


	    printf("%s sent back 0x%08x, size 0x%08x ok. bytesWritten %d. totalBytesSent %d\n",
		   __FUNCTION__,
		   sequenceNumber,
		   packetSize,
		   bytesWritten,
		   totalBytesSent);
	}

	free(readBuffer);
	free(writeBuffer);
	//printf("total bytes received %d\n", totalBytesReceived);
    }
    else
    {
	printf("%s cannot create memory.\n", __FUNCTION__);
    }

}

BounceType WorkOutBounceType(char *operation)
{
    BounceType returnValue = eOneWrite;
    if (!strcmp(operation, OPERATION_BOUNCE_WITH_WRITEV))
    {
	returnValue = eWriteV;
    }
    else if (!strcmp(operation, OPERATION_BOUNCE_WITH_MANY_WRITES))
    {
	returnValue = eManyWrites;
    }
    else if (!strcmp(operation, OPERATION_BOUNCE_WITH_ONE_WRITE))
    {
	returnValue = eOneWrite;
    }
    else
    {
	printf("%s cannot identify bounce type %s, so will do one write each packet\n", __FUNCTION__, operation);
    }
    printf("%s will use %s, which is BounceType %d\n",
	   __FUNCTION__,
	   operation,
	   returnValue);
    return returnValue;
}

int FileTransfer(int domid, int listenPort, char *fileName, char *operation)
{
    int returnValue = false;
    int connection = 0;
    BounceType bounceType = 0;

    printf("%s begin.\n", __FUNCTION__);

    bounceType = WorkOutBounceType(operation);
    //Let's start listening for our socket.
    connection = WaitForIncomingConnection(listenPort, domid);

    if (connection > 0)
    {
	printf("We are connected... Now can do data transfer\n");
	if (!strcmp(OPERATION_RECEIVE, operation))
	{
	    printf("Now going to receive file to %s\n", fileName);
	    ReceiveFile(connection, fileName);
	}
	else if (!strcmp(OPERATION_SEND, operation))
	{
	    printf("Now going to send file to %s\n", fileName);
	    SendFile(connection, fileName);
	}
	else if (!strncmp(OPERATION_BOUNCE_BASE, operation, OPERATION_BOUNCE_BASE_LENGTH))
	{
	    printf("Now going to bounce data with other side\n");
	    BounceData(connection, bounceType);
	}
    }

    CloseConnection(connection);

    printf("%s end. return %d.\n", __FUNCTION__, returnValue);
    return returnValue;

}
