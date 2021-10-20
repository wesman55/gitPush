#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>

#define BUF_SIZE 500

int main(int argc, char *argv[]) {
	struct addrinfo hints;
	struct addrinfo *result, *rp;
	int hostindex;
	int sfd, s, j;
	size_t len;
	ssize_t nread;
	char buf[BUF_SIZE];
	int af;

	if (!(argc >= 3 || (argc >= 4 &&
			(strcmp(argv[1], "-4") == 0 || strcmp(argv[1], "-6") == 0)))) {
		fprintf(stderr, "Usage: %s [ -4 | -6 ] host port msg...\n", argv[0]);
		exit(EXIT_FAILURE);
	}

	/* Use IPv4 by default (or if -4 is used).  If IPv6 is specified,
	 * then use that instead. */
	af = AF_UNSPEC;
	if (strcmp(argv[1], "-4") == 0 ||
			strcmp(argv[1], "-6") == 0) {
		if (strcmp(argv[1], "-6") == 0) {
			af = AF_INET6;
		} else { // (strcmp(argv[1], "-4") == 0) {
			af = AF_INET;
		}
		hostindex = 2;
	} else {
		hostindex = 1;
	}

	/* Obtain address(es) matching host/port */

	memset(&hints, 0, sizeof(struct addrinfo));
	hints.ai_family = af;    /* Allow IPv4, IPv6, or both, depending on
				    what was specified on the command line. */
	hints.ai_socktype = SOCK_STREAM; /* Datagram socket */
	hints.ai_flags = 0;
	hints.ai_protocol = 0;          /* Any protocol */

	s = getaddrinfo(argv[hostindex], argv[hostindex + 1], &hints, &result);
	if (s != 0) {
		fprintf(stderr, "getaddrinfo: %s\n", gai_strerror(s));
		exit(EXIT_FAILURE);
	}

	/* getaddrinfo() returns a list of address structures.
	   Try each address until we successfully connect(2).
	   If socket(2) (or connect(2)) fails, we (close the socket
	   and) try the next address. */

	for (rp = result; rp != NULL; rp = rp->ai_next) {
		sfd = socket(rp->ai_family, rp->ai_socktype,
				rp->ai_protocol);
		if (sfd == -1)
			continue;

		if (connect(sfd, rp->ai_addr, rp->ai_addrlen) != -1)
			break;                  /* Success */

		close(sfd);
	}

	if (rp == NULL) {               /* No address succeeded */
		fprintf(stderr, "Could not connect\n");
		exit(EXIT_FAILURE);
	}

	freeaddrinfo(result);           /* No longer needed */

	int MAX_SIZE = 4096;
	char * readBuff = malloc(MAX_SIZE);
	int readBytes = 0;

	readBytes = fread(readBuff, sizeof(char), MAX_SIZE, stdin);
	
	int sent = 0;

	for(;;) {
		sent = sent + write(sfd, readBuff, readBytes);
		if (sent >= readBytes) {
			break;
		}
	
	}	

	int MAX_READ = 16384;
	char * socketRead = malloc(MAX_READ);
	int totalRead = 0;
	int numRead = 0;
	
	for(;;) {
		numRead = read(sfd, socketRead + totalRead, 512);
		totalRead = totalRead + numRead;
		if (numRead <= 0) {
			break;
		}
	}
	socketRead[totalRead] = '\0';

	write(STDOUT_FILENO, socketRead, totalRead);



	/* Send remaining command-line arguments as separate
	   datagrams, and read responses from server */

	/*for (j = hostindex + 2; j < argc; j++) {
		len = strlen(argv[j]) + 1;
		 +1 for terminating null byte 

	:	if (len + 1 > BUF_SIZE) {
			fprintf(stderr,
i					"Ignoring long message in argument %d\n", j);
			continue;
		}

		if (write(sfd, argv[j], len) != len) {
			fprintf(stderr, "partial/failed write\n");
			exit(EXIT_FAILURE);
		}
		printf("Sent %ld bytes to server\n", len);

		nread = read(sfd, buf, BUF_SIZE);
		if (nread == -1) {
			perror("read");
			exit(EXIT_FAILURE);
		}

		printf("Received %zd bytes: %s\n", nread, buf);
	} */

	exit(EXIT_SUCCESS);
}
