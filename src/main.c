#include <stdio.h>
#include <stdlib.h>
#include <winsock2.h>

#define BUFLEN 512	// Max length of buffer
#define PORT 53	    // The port on which to listen for incoming data

int main()
{
	SOCKET s;
	struct sockaddr_in server, si_other;
	int slen , recv_len;
	char buf[BUFLEN];
	WSADATA wsa;

	slen = sizeof(si_other);
	
	// Initialise winsock
	// printf("\nInitialising Winsock...");
	if (WSAStartup(MAKEWORD(2,2),&wsa) != 0)
	{
		fprintf(stderr, "Failed. Error Code : %d", WSAGetLastError());
		exit(EXIT_FAILURE);
	}
	// printf("Initialised.\n");
	
	// Create a socket
	if((s = socket(AF_INET , SOCK_DGRAM , 0)) == INVALID_SOCKET)
	{
		fprintf(stderr, "Could not create socket : %d" , WSAGetLastError());
        exit(EXIT_FAILURE);
	}
	// printf("Socket created.\n");
	
	// Prepare the sockaddr_in structure
	server.sin_family = AF_INET;
	server.sin_addr.s_addr = inet_addr("127.0.0.1");
	server.sin_port = htons( PORT );
	
	// Bind
	if( bind(s ,(struct sockaddr *)&server , sizeof(server)) == SOCKET_ERROR)
	{
		fprintf(stderr, "Bind failed with error code : %d" , WSAGetLastError());
		exit(EXIT_FAILURE);
	}
	// printf("Bind done");

	// Keep listening for data
	while(1)
	{
		// printf("Waiting for data...");
		fflush(stdout);
		
		//clear the buffer by filling null, it might have previously received data
		memset(buf,'\0', BUFLEN);
		
		// Try to receive some data, this is a blocking call
		if ((recv_len = recvfrom(s, buf, BUFLEN, 0, (struct sockaddr *) &si_other, &slen)) == SOCKET_ERROR)
		{
			printf("recvfrom() failed with error code : %d" , WSAGetLastError());
			exit(EXIT_FAILURE);
		}
		
		//print details of the client/peer and the data received
		printf("Received packet from %s:%d\n", inet_ntoa(si_other.sin_addr), ntohs(si_other.sin_port));
		printf("Received %d bytes\n", recv_len);
        #define HEADER_SIZE 2
        for (int i = HEADER_SIZE; i < recv_len; i++) printf("%02x ", (unsigned char)buf[i]);
        printf("\n");
        for (int i = HEADER_SIZE; i < recv_len; i++) printf("%c", (unsigned char)buf[i]);
        printf("\n");
	}

	closesocket(s);
	WSACleanup();
	
	return 0;
}