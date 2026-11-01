#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <winsock2.h>
#include <ws2tcpip.h>

#include "load.h"

char domains[MAX_DOMAINS][MAX_DOMAIN_LENGTH];
int ndomains = 0;

#define UPSTREAM_DNS_SERVER_IP "1.1.1.1"
#define BUFLEN 512	// Max length of buffer
#define PORT 53	    // The port on which to listen for incoming data

#ifndef SIO_UDP_CONNRESET
#define SIO_UDP_CONNRESET _WSAIOW(IOC_VENDOR, 12)
#endif


static void disable_udp_connreset(SOCKET sock) {
    BOOL off = FALSE;
    DWORD ret = 0;
    WSAIoctl(sock, SIO_UDP_CONNRESET, &off, sizeof off, NULL, 0, &ret, NULL, NULL);
}


#define DNS_HEADER_SIZE 12

/*
 * Decode the question name (QNAME) of a DNS packet into dotted, lowercase form,
 * e.g. bytes 03 'w' 'w' 'w' 07 'y' 'o' 'u' 't' 'u' 'b' 'e' 03 'c' 'o' 'm' 00
 * become "www.youtube.com". Each label is read using its own length byte, so
 * label lengths no longer matter. Returns 0 on success, -1 on a malformed name.
 */
static int parse_qname(const unsigned char *buf, int len, char *out, size_t outsz)
{
    int i = DNS_HEADER_SIZE;
    size_t o = 0;
    while (i < len) {
        unsigned lab = buf[i++];
        if (lab == 0) { out[o] = '\0'; return 0; }               /* root label: end of name */
        if (lab > 63 || i + (int)lab > len || o + lab + 2 > outsz)
            return -1;                                           /* compression pointer, truncated, or too long */
        if (o) out[o++] = '.';
        for (unsigned k = 0; k < lab; k++)
            out[o++] = (char)tolower(buf[i++]);
    }
    return -1;                                                   /* ran off the end without a root label */
}

/*
 * Check the name and every parent domain against the blocklist:
 * "www.youtube.com" checks "www.youtube.com", "youtube.com", then "com".
 * blocked.txt entries have their dots removed (see clean_blocked.py), so each
 * candidate is compared with its dots removed ("youtubecom").
 */
static int is_blocked(const char *name)
{
    char flat[MAX_DOMAIN_LENGTH];
    const char *suffix = name;
    while (*suffix) {
        size_t o = 0;
        for (const char *c = suffix; *c && o + 1 < sizeof flat; c++)
            if (*c != '.') flat[o++] = *c;
        flat[o] = '\0';

        for (int i = 0; i < ndomains; i++)
            if (strcmp(flat, domains[i]) == 0) return 1;

        const char *dot = strchr(suffix, '.');
        if (!dot) break;
        suffix = dot + 1;                                        /* move to the parent domain */
    }
    return 0;
}


/* ---------------------------------------------------------------------------
 * Service plumbing
 * ------------------------------------------------------------------------- */

#define SERVICE_NAME "DNSFilter"

static SERVICE_STATUS_HANDLE g_status_handle = NULL;    /* NULL when running in a console */
static SERVICE_STATUS g_status;
static volatile LONG g_stopping = 0;
static SOCKET g_listen = INVALID_SOCKET;
static char g_blocklist_path[MAX_PATH + 32];   /* exe dir + "\..\blocked.txt" */

static void set_status(DWORD state, DWORD win32_exit)
{
    if (!g_status_handle) return;
    g_status.dwServiceType = SERVICE_WIN32_OWN_PROCESS;
    g_status.dwCurrentState = state;
    g_status.dwControlsAccepted = (state == SERVICE_RUNNING) ? (SERVICE_ACCEPT_STOP | SERVICE_ACCEPT_SHUTDOWN) : 0;
    g_status.dwWin32ExitCode = win32_exit;
    g_status.dwWaitHint = (state == SERVICE_START_PENDING || state == SERVICE_STOP_PENDING) ? 10000 : 0;
    SetServiceStatus(g_status_handle, &g_status);
}

/* Ask the receive loop to exit: closing the socket unblocks recvfrom(). */
static void request_stop(void)
{
    InterlockedExchange(&g_stopping, 1);
    if (g_listen != INVALID_SOCKET) closesocket(g_listen);
}

static DWORD WINAPI service_ctrl(DWORD ctrl, DWORD type, LPVOID data, LPVOID ctx)
{
    (void)type; (void)data; (void)ctx;
    switch (ctrl) {
    case SERVICE_CONTROL_STOP:
    case SERVICE_CONTROL_SHUTDOWN:
        set_status(SERVICE_STOP_PENDING, NO_ERROR);
        request_stop();
        return NO_ERROR;
    case SERVICE_CONTROL_INTERROGATE:
        return NO_ERROR;
    }
    return ERROR_CALL_NOT_IMPLEMENTED;
}

static BOOL WINAPI console_ctrl(DWORD type)
{
    (void)type;
    request_stop();                          /* Ctrl+C in a console: shut down cleanly */
    return TRUE;
}

/* Default blocklist location: next to the exe, or one folder up (the src\ dev layout). */
static void resolve_blocklist_path(int argc, char *argv[])
{
    if (argc > 1) {
        snprintf(g_blocklist_path, sizeof g_blocklist_path, "%s", argv[1]);
        return;
    }
    char dir[MAX_PATH];
    DWORD n = GetModuleFileNameA(NULL, dir, sizeof dir);
    if (n == 0 || n >= sizeof dir) { snprintf(g_blocklist_path, sizeof g_blocklist_path, "blocked.txt"); return; }
    char *slash = strrchr(dir, '\\');
    if (slash) *slash = '\0';

    snprintf(g_blocklist_path, sizeof g_blocklist_path, "%s\\blocked.txt", dir);
    if (GetFileAttributesA(g_blocklist_path) == INVALID_FILE_ATTRIBUTES)
        snprintf(g_blocklist_path, sizeof g_blocklist_path, "%s\\..\\blocked.txt", dir);
}


/* ---------------------------------------------------------------------------
 * DNS server. Returns 0 on a clean stop, otherwise a Win32 error code.
 * ------------------------------------------------------------------------- */

static int run_server(void)
{
    // Initialize the blocklist
    const char *path = g_blocklist_path;
    if (load_blocklist(path) < 0) {
        fprintf(stderr, "Failed to load blocklist: %s\n", path);
        return ERROR_FILE_NOT_FOUND;         // non-zero exit shows up as a failed service
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
		return WSAGetLastError();
	}
	// printf("Initialised.\n");

	// Create a socket
	if((s = socket(AF_INET , SOCK_DGRAM , 0)) == INVALID_SOCKET)
	{
		fprintf(stderr, "Could not create socket : %d" , WSAGetLastError());
		int err = WSAGetLastError();
		WSACleanup();
		return err;
	}
	g_listen = s;
	// printf("Socket created.\n");
	
	// Prepare the sockaddr_in structure
	server.sin_family = AF_INET;
	server.sin_addr.s_addr = inet_addr("127.0.0.1");
	server.sin_port = htons( PORT );

	struct sockaddr_in si_upstream;
	memset((char *) &si_upstream, 0, sizeof(si_upstream));
	si_upstream.sin_family = AF_INET;
	si_upstream.sin_port = htons(PORT);
	si_upstream.sin_addr.S_un.S_addr = inet_addr(UPSTREAM_DNS_SERVER_IP);

	/* once, at startup, next to creating `s` */
	SOCKET up = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);   /* no bind(): the OS picks source IP and port */
	DWORD timeout_ms = 2000;
	setsockopt(up, SOL_SOCKET, SO_RCVTIMEO, (const char *)&timeout_ms, sizeof timeout_ms);
	
	// Bind
	if( bind(s ,(struct sockaddr *)&server , sizeof(server)) == SOCKET_ERROR)
	{
		int err = WSAGetLastError();
		fprintf(stderr, "Bind failed with error code : %d" , err);
		closesocket(up);
		closesocket(s);
		WSACleanup();
		return err;
	}
	// printf("Bind done");

	disable_udp_connreset(s);
	disable_udp_connreset(up);

	set_status(SERVICE_RUNNING, NO_ERROR);   /* tell the SCM we're up (no-op in a console) */

	int exit_code = 0;

	// Keep listening for data
	while (!g_stopping)
	{
		// printf("Waiting for data...");
		fflush(stdout);

		//clear the buffer by filling null, it might have previously received data
		memset(buf,'\0', BUFLEN);

		// Try to receive some data, this is a blocking call
		slen = sizeof(si_other);
		if ((recv_len = recvfrom(s, buf, BUFLEN, 0, (struct sockaddr *) &si_other, &slen)) == SOCKET_ERROR)
		{
			int err = WSAGetLastError();
			if (g_stopping) break;                          /* socket closed by request_stop() */
			if (err == WSAEMSGSIZE || err == WSAECONNRESET) continue;   /* one bad packet: skip it */
			fprintf(stderr, "recvfrom() failed with error code : %d" , err);
			exit_code = err;
			break;
		}
		if (recv_len < DNS_HEADER_SIZE) continue;           /* too short to be a DNS query */
		
		// Decode the queried domain name, e.g. "www.youtube.com"
		char qname[MAX_DOMAIN_LENGTH];
		uint8_t isBlocked = 0;
		if (parse_qname((const unsigned char *)buf, recv_len, qname, sizeof qname) == 0) {
			// printf("Query: %s\n", qname);
			isBlocked = is_blocked(qname);
			// if (isBlocked) printf("Blocked: %s\n", qname);
		} else {
			// printf("Query: <malformed name, forwarding>\n");
		}

		/* in the loop, for an allowed query */
		if (isBlocked) {
			unsigned char *p = (unsigned char *)buf;

			p[2] = 0x80 | (p[2] & 0x01);   /* QR=1 (response), opcode=0, AA=0, TC=0, keep RD */
			p[3] = 0x80 | 0x03;            /* RA=1, Z=0, RCODE=3 (NXDOMAIN) */

			sendto(s, buf, recv_len, 0, (struct sockaddr *)&si_other, sizeof si_other);

		} else {
			if (sendto(up, buf, recv_len, 0,
					(struct sockaddr *)&si_upstream, sizeof(si_upstream)) == SOCKET_ERROR) {
				printf("upstream sendto failed: %d\n", WSAGetLastError());
			}

			/* Wait for the reply to THIS query. A late reply to an earlier query that
			 * timed out has a different ID (bytes 0-1); skip it instead of sending
			 * it to the wrong client. */
			char reply[4096];
			int reply_len;
			do {
				reply_len = recvfrom(up, reply, sizeof reply, 0, NULL, NULL);
			} while (reply_len >= 2 && memcmp(reply, buf, 2) != 0);

			if (reply_len == SOCKET_ERROR) {
				printf("upstream recvfrom failed: %d\n", WSAGetLastError());   /* 10060 = timeout */
			} else {
				/* send the answer back to whoever asked */
				sendto(s, reply, reply_len, 0, (struct sockaddr *)&si_other, sizeof(si_other));
			}
		}

	}

	closesocket(up);
	if (!g_stopping) closesocket(s);         /* request_stop() already closed it otherwise */
	g_listen = INVALID_SOCKET;
	WSACleanup();

	return exit_code;
}


static void WINAPI service_main(DWORD argc, LPSTR *argv)
{
    (void)argc; (void)argv;
    g_status_handle = RegisterServiceCtrlHandlerExA(SERVICE_NAME, service_ctrl, NULL);
    if (!g_status_handle) return;

    set_status(SERVICE_START_PENDING, NO_ERROR);
    int rc = run_server();
    /* A non-zero exit code makes the SCM apply the recovery actions (restart). */
    set_status(SERVICE_STOPPED, rc ? (DWORD)rc : NO_ERROR);
}


int main(int argc, char *argv[])
{
    resolve_blocklist_path(argc, argv);

    SERVICE_TABLE_ENTRYA table[] = {
        { SERVICE_NAME, service_main },
        { NULL, NULL }
    };
    if (StartServiceCtrlDispatcherA(table)) return 0;   /* ran as a service until stopped */

    if (GetLastError() != ERROR_FAILED_SERVICE_CONTROLLER_CONNECT) return 1;

    /* Not started by the SCM: run in this console (Ctrl+C to stop). */
    printf("Running in console mode, blocklist: %s\n", g_blocklist_path);
    SetConsoleCtrlHandler(console_ctrl, TRUE);
    return run_server();
}