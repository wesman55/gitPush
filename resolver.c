#include<arpa/inet.h>
#include<netinet/in.h>
#include<stdio.h>
#include<string.h>
#include<stdlib.h>
#include<sys/types.h>
#include<sys/socket.h>
#include<netdb.h>
#include<unistd.h>

typedef unsigned int dns_rr_ttl;
typedef unsigned short dns_rr_type;
typedef unsigned short dns_rr_class;
typedef unsigned short dns_rdata_len;
typedef unsigned short dns_rr_count;
typedef unsigned short dns_query_id;
typedef unsigned short dns_flags;

typedef struct {
	char *name;
	dns_rr_type type;
	dns_rr_class class;
	dns_rr_ttl ttl;
	dns_rdata_len rdata_len;
	unsigned char *rdata;
} dns_rr;

struct dns_answer_entry;
struct dns_answer_entry {
	char *value;
	struct dns_answer_entry *next;
};
typedef struct dns_answer_entry dns_answer_entry;

void free_answer_entries(dns_answer_entry *ans) {
	dns_answer_entry *next;
	while (ans != NULL) {
		next = ans->next;
		free(ans->value);
		free(ans);
		ans = next;
	}
}

void print_bytes(unsigned char *bytes, int byteslen) {
	int i, j, byteslen_adjusted;
	unsigned char c;

	if (byteslen % 8) {
		byteslen_adjusted = ((byteslen / 8) + 1) * 8;
	} else {
		byteslen_adjusted = byteslen;
	}
	for (i = 0; i < byteslen_adjusted + 1; i++) {
		if (!(i % 8)) {
			if (i > 0) {
				for (j = i - 8; j < i; j++) {
					if (j >= byteslen_adjusted) {
						printf("  ");
					} else if (j >= byteslen) {
						printf("  ");
					} else if (bytes[j] >= '!' && bytes[j] <= '~') {
						printf(" %c", bytes[j]);
					} else {
						printf(" .");
					}
				}
			}
			if (i < byteslen_adjusted) {
				printf("\n%02X: ", i);
			}
		} else if (!(i % 4)) {
			printf(" ");
		}
		if (i >= byteslen_adjusted) {
			continue;
		} else if (i >= byteslen) {
			printf("   ");
		} else {
			printf("%02X ", bytes[i]);
		}
	}
	printf("\n");
}

void canonicalize_name(char *name) {
	/*
	 * Canonicalize name in place.  Change all upper-case characters to
	 * lower case and remove the trailing dot if there is any.  If the name
	 * passed is a single dot, "." (representing the root zone), then it
	 * should stay the same.
	 *
	 * INPUT:  name: the domain name that should be canonicalized in place
	 */
	
	int namelen, i;

	// leave the root zone alone
	if (strcmp(name, ".") == 0) {
		return;
	}

	namelen = strlen(name);
	// remove the trailing dot, if any
	if (name[namelen - 1] == '.') {
		name[namelen - 1] = '\0';
	}

	// make all upper-case letters lower case
	for (i = 0; i < namelen; i++) {
		if (name[i] >= 'A' && name[i] <= 'Z') {
			name[i] += 32;
		}
	}
}

int name_ascii_to_wire(char *name, unsigned char *wire) {
	/* 
	 * Convert a DNS name from string representation (dot-separated labels)
	 * to DNS wire format, using the provided byte array (wire).  Return
	 * the number of bytes used by the name in wire format.
	 *
	 * INPUT:  name: the string containing the domain name
	 * INPUT:  wire: a pointer to the array of bytes where the
	 *              wire-formatted name should be constructed
	 * OUTPUT: the length of the wire-formatted name.
	 */
}

char *name_ascii_from_wire(unsigned char *wire, int *indexp) {
	/* 
	 * Extract the wire-formatted DNS name at the offset specified by
	 * *indexp in the array of bytes provided (wire) and return its string
	 * representation (dot-separated labels) in a char array allocated for
	 * that purpose.  Update the value pointed to by indexp to the next
	 * value beyond the name.
	 *
	 * INPUT:  wire: a pointer to an array of bytes
	 * INPUT:  indexp, a pointer to the index in the wire where the
	 *              wire-formatted name begins
	 * OUTPUT: a string containing the string representation of the name,
	 *              allocated on the heap.
	 */
}

dns_rr rr_from_wire(unsigned char *wire, int *indexp, int query_only) {
	/* 
	 * Extract the wire-formatted resource record at the offset specified by
	 * *indexp in the array of bytes provided (wire) and return a 
	 * dns_rr (struct) populated with its contents. Update the value
	 * pointed to by indexp to the next value beyond the resource record.
	 *
	 * INPUT:  wire: a pointer to an array of bytes
	 * INPUT:  indexp: a pointer to the index in the wire where the
	 *              wire-formatted resource record begins
	 * INPUT:  query_only: a boolean value (1 or 0) which indicates whether
	 *              we are extracting a full resource record or only a
	 *              query (i.e., in the question section of the DNS
	 *              message).  In the case of the latter, the ttl,
	 *              rdata_len, and rdata are skipped.
	 * OUTPUT: the resource record (struct)
	 */
}


int rr_to_wire(dns_rr rr, unsigned char *wire, int query_only) {
	/* 
	 * Convert a DNS resource record struct to DNS wire format, using the
	 * provided byte array (wire).  Return the number of bytes used by the
	 * name in wire format.
	 *
	 * INPUT:  rr: the dns_rr struct containing the rr record
	 * INPUT:  wire: a pointer to the array of bytes where the
	 *             wire-formatted resource record should be constructed
	 * INPUT:  query_only: a boolean value (1 or 0) which indicates whether
	 *              we are constructing a full resource record or only a
	 *              query (i.e., in the question section of the DNS
	 *              message).  In the case of the latter, the ttl,
	 *              rdata_len, and rdata are skipped.
	 * OUTPUT: the length of the wire-formatted resource record.
	 *
	 */
}

unsigned short create_dns_query(char *qname, dns_rr_type qtype, unsigned char *wire) {
	/* 
	 * Create a wire-formatted DNS (query) message using the provided byte
	 * array (wire).  Create the header and question sections, including
	 * the qname and qtype.
	 *
	 * INPUT:  qname: the string containing the name to be queried
	 * INPUT:  qtype: the integer representation of type of the query (type A == 1)
	 * INPUT:  wire: the pointer to the array of bytes where the DNS wire
	 *               message should be constructed
	 * OUTPUT: the length of the DNS wire message
	 */

	canonicalize_name(qname);

	unsigned char randomStart = rand() % 0xff;
	unsigned char randomEnd = rand() % 0xff;
	unsigned char *header = malloc(12);
	header[0] = randomStart;
	header[1] = randomEnd;
	header[2] = 0x01;
        header[3] = 0x00;
       	header[4] = 0x00;
	header[5] = 0x01;
	header[6] = 0x00;
	header[7] = 0x00;
	header[8] = 0x00;
       	header[9] = 0x00;
       	header[10] = 0x00;
       	header[11] = 0x00;
	unsigned char *footer = malloc(4);
	footer[0] = 0x00;
	footer[1] = 0x01;
       	footer[2] = 0x00;
	footer[3] = 0x01;

	int currentLengthOfWire = 0;

	memcpy(wire + currentLengthOfWire, header, 12);
	currentLengthOfWire = currentLengthOfWire + 12;

	if (strlen(qname) == 1 && !strcmp(qname, ".")) {
		wire[currentLengthOfWire] = 0x00;
		currentLengthOfWire++;
		memcpy(wire + currentLengthOfWire, footer, + 4);
		currentLengthOfWire += 4;

		free(header);
		free(footer);

		return currentLengthOfWire;

	}

	unsigned char *parseQName = malloc(400);
	strcpy(parseQName, qname);
	char * nextStringPointer = strtok(parseQName, ".");
	int lengthNextStringPointer = strlen(nextStringPointer);

	wire[currentLengthOfWire] = lengthNextStringPointer;
	currentLengthOfWire++;
	memcpy(wire + currentLengthOfWire, nextStringPointer, lengthNextStringPointer);
	currentLengthOfWire = currentLengthOfWire + lengthNextStringPointer;

	while(nextStringPointer != NULL) {
		nextStringPointer = strtok(NULL, ".");
		if (nextStringPointer != NULL) {
			lengthNextStringPointer = strlen(nextStringPointer);
			wire[currentLengthOfWire] = lengthNextStringPointer;
			currentLengthOfWire++;
			memcpy(wire + currentLengthOfWire, nextStringPointer, lengthNextStringPointer);
			currentLengthOfWire = currentLengthOfWire + lengthNextStringPointer;	
		}	
	}
	wire[currentLengthOfWire] = 0;
	currentLengthOfWire++;

	memcpy(wire + currentLengthOfWire, footer, 4);
	currentLengthOfWire = currentLengthOfWire + 4;

	free(header);
	free(footer);
	free(parseQName);

	//print_bytes(wire, currentLengthOfWire);
	
	return currentLengthOfWire;


}

dns_answer_entry *createAnswerList(char *qname, int numAnswers, int currentAnswer, int index, dns_answer_entry *dns_answer, unsigned char *wire) {
        if (numAnswers == currentAnswer) {
                return dns_answer;
        }

        index = index + 2;
        dns_rr_type type = *(unsigned short *)(wire + index);
        index = index + 2;
        dns_rr_class class = *(unsigned short *)(wire + index);
        index = index + 4;
        dns_rr_ttl ttl = *(unsigned int *)(wire + index);
        index = index + 2;
        unsigned char responseDataLength = *(unsigned char *)(wire + index);
 
        index = index + 1;
        unsigned char responseData[responseDataLength];
        memcpy(responseData, wire + index, responseDataLength);

        responseData[responseDataLength] = '\0';
        char * buffer = malloc(500);
        char *result = (char *) inet_ntop(AF_INET, responseData, buffer, 500);

        struct dns_answer_entry *entry = malloc(10 * sizeof(entry));
        char * value = malloc (500);
        strcpy(value, result);
        entry->value = value;
	if (dns_answer != NULL) {
		entry->next = dns_answer;
	}
	free(buffer);
        return createAnswerList(qname, numAnswers, currentAnswer + 1, index + 6, entry, wire);
}


dns_answer_entry *get_answer_address(char *qname, dns_rr_type qtype, unsigned char *wire) {
	/* 
	 * Extract the IPv4 address from the answer section, following any
	 * aliases that might be found, and return the string representation of
	 * the IP address.  If no address is found, then return NULL.
	 *
	 * INPUT:  qname: the string containing the name that was queried
	 * INPUT:  qtype: the integer representation of type of the query (type A == 1)
	 * INPUT:  wire: the pointer to the array of bytes representing the DNS wire message
	 * OUTPUT: a linked list of dns_answer_entrys the value member of each
	 * reflecting either the name or IP address.  If
	 */
	short numAnswers = *(unsigned short *) (wire + 7);
	if (numAnswers == 0) {
		return NULL;
	}

	int responseIndex = 12 + strlen(qname) + 7;
	responseIndex = responseIndex + 2;
	dns_rr_type type = *(unsigned short *)(wire + responseIndex);
	responseIndex += 2;
	dns_rr_class class = *(unsigned short *)(wire + responseIndex);
	responseIndex += 4;
	dns_rr_ttl ttl = *(unsigned int *)(wire + responseIndex);
	responseIndex += 2;
	dns_rdata_len responseDataLength = *(unsigned char *)(wire + responseIndex);

	responseIndex = responseIndex + 1;
	unsigned char responseData[responseDataLength];
	memcpy(responseData, wire + responseIndex, responseDataLength);

	if (type == 5) {
		unsigned char * alias = malloc(500);
		int index = responseIndex;
		int length = wire[index];
		int aliasLength = 0;

		memcpy(alias, wire + responseIndex + 1, length);
		aliasLength = aliasLength + length;
		alias[aliasLength] = '.';
		aliasLength++;

		index = responseData[responseDataLength - 1];
		length = wire[index];

		do {
			memcpy(alias + aliasLength, wire + index + 1, length);
			aliasLength += length;
			alias[aliasLength] = '.';
			aliasLength++;
			index = index + length + 1;
			length = wire[index];
		} while(length != 0);


		alias[aliasLength - 1] = '\0';
		strcpy(qname, alias);

		struct dns_answer_entry *header = (dns_answer_entry *) malloc(10 * sizeof (dns_answer_entry));
		char *value = malloc(500);
		strcpy(value, qname);
		header->value = value;
		header->next = NULL;

		free(alias);

		if (numAnswers == 1) {
			return header;
		} else {
			return createAnswerList(qname, numAnswers, 1, index + 18 + responseDataLength, header, wire);
		}	
	} else {
		responseData[responseDataLength] = '\0';
		char * buffer = malloc (500);
		char* result = (char *) inet_ntop(AF_INET, responseData, buffer, 500);

		struct dns_answer_entry *header = malloc(10 * sizeof(header));
		char * value = malloc (500);
		strcpy(value, result);
		header->value = value;
		header->next = NULL;

		free(buffer);

		if (numAnswers == 1) {
			return header;
		}
		struct dns_answer_entry *answerList = createAnswerList(qname, numAnswers, 1, responseIndex -1, header, wire);
		return answerList;
	}
}

int send_recv_message(unsigned char *request, int requestlen, unsigned char *response, char *server, char *port) {
	/*i 
	 * Send a message (request) over UDP to a server (server) and port
	 * (port) and wait for a response, which is placed in another byte
	 * array (response).  Create a socket, "connect()" it to the
	 * appropriate destination, and then use send() and recv();
	 *
	 * INPUT:  request: a pointer to an array of bytes that should be sent
	 * INPUT:  requestlen: the length of request, in bytes.
	 * INPUT:  response: a pointer to an array of bytes in which the
	 *             response should be received
	 * OUTPUT: the size (bytes) of the response received
	 */
	struct addrinfo hints;
	struct addrinfo *result, *rp;
	int sfd, s;

	memset(&hints, 0, sizeof(struct addrinfo));
	hints.ai_family = AF_INET;
	hints.ai_socktype = SOCK_DGRAM;
	hints.ai_flags = 0;
	hints.ai_protocol = 0;

	s= getaddrinfo(server, port, &hints, &result);
	if (s!= 0) {
		fprintf(stderr, "getaddrinfo: %s\n", gai_strerror(s));
		exit(1);
	}
	for (rp = result; rp!= NULL; rp = rp->ai_next) {
		sfd = socket(rp->ai_family, rp->ai_socktype, rp->ai_protocol);
		if (sfd == -1) {
			continue;
		}
		if (connect(sfd, rp->ai_addr, rp->ai_addrlen) != -1) {
			break;
		}
		close(sfd);
	}
	if (rp == NULL) {
		fprintf(stderr, "Could not connect\n");
		exit(1);
	}
	freeaddrinfo(result);

	unsigned char *buffer = malloc(1500);

	send(sfd, request, requestlen, 0);
	int sizeResponse = recv(sfd, buffer, 1024, 0);
       	memcpy(response, buffer, sizeResponse);

	free(buffer);

	return sizeResponse;	

}

dns_answer_entry *resolve(char *qname, char *server, char *port) {
	unsigned char *wire = malloc(3000);
	unsigned short wireLength = create_dns_query(qname, 0x01, wire);

	unsigned char *response = malloc(3000);
	int responseLength = send_recv_message(wire, wireLength, response, server, port);

	//print_bytes(response, responseLength);


	dns_answer_entry* dns_answers = get_answer_address(qname, 0x01, response);

	free(wire);
	free(response);

	return dns_answers;
}

int main(int argc, char *argv[]) {
	char *port;
	dns_answer_entry *ans_list, *ans;
	if (argc < 3) {
		fprintf(stderr, "Usage: %s <domain name> <server> [ <port> ]\n", argv[0]);
		exit(1);
	}
	if (argc > 3) {
		port = argv[3];
	} else {
		port = "53";
	}
	ans = ans_list = resolve(argv[1], argv[2], port);
	while (ans != NULL) {
		printf("%s\n", ans->value);
		ans = ans->next;
	}
	if (ans_list != NULL) {
		free_answer_entries(ans_list);
	}
}
