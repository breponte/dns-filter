#include <stdio.h>
#include <stdlib.h>
#include <winsock2.h>

#include "load.h"

char domains[MAX_DOMAINS][MAX_DOMAIN_LENGTH];
int ndomains = 0;

#define BUFLEN 512	// Max length of buffer
#define PORT 53	    // The port on which to listen for incoming data

int main()
{
    // Initialize the blocklist
    const char *path = "C:\\Users\\brepo\\OneDrive\\Desktop\\playground\\dns-filter\\blocked.txt";
    if (load_blocklist(path) < 0) {
        fprintf(stderr, "Failed to load blocklist: %s\n", path);
        return 1;                            // non-zero exit shows up as a failed service
    }

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
		
        #define HEADER_SIZE 2
        for (int i = HEADER_SIZE; i < recv_len; i++) printf("%c", (unsigned char)buf[i]);
        for (int i = 0; i < ndomains; i++) {
            if (strcmp((char *)&buf[HEADER_SIZE], domains[i]) == 0) {
                printf("Blocked: %s\n", (char *)&buf[HEADER_SIZE]);
                break;
            }
        }
        printf("\n");
	}

	closesocket(s);
	WSACleanup();
	
	return 0;
}