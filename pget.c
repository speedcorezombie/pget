#include <pcap/pcap.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <mysql.h>

#define MAX_HTTP_SIZE 2048 		 // Max allowed HTTP packet size
#define MAX_FIELD_SIZE 128               // Max allowed field size in HTTP header
#define MAX_REQ_SIZE 256		 // Max allowed request string size
#define ETH_HDR_SIZE 14			 // Ethernet header size
#define MIN(X,Y) ((X) < (Y) ? (X) : (Y))

MYSQL* mysql_conn();

int main() {

	char* device;                    // Sniffing device
	char errbuf[PCAP_ERRBUF_SIZE];   // Error message buffer
	char httpbuf[MAX_HTTP_SIZE];     // HTTP packet buffer
	char request[MAX_REQ_SIZE];      // Buffer for extract HTTP request
	char host[MAX_FIELD_SIZE];       // Buffer for extract HTTP Host
	char useragent[MAX_FIELD_SIZE];   // Buffer for extract HTTP User-Agent
	char query[2048];
	pcap_t* handle;                  // Session handle
	struct bpf_program fp;           // The compiled filter expression
	char filter_exp[] = "dst port 80";   // The filter expression
	bpf_u_int32 mask;                // The netmask of our sniffing device
	bpf_u_int32 net;                 // The IP of our sniffing device
	struct pcap_pkthdr header;       // The header that pcap gives us
	const u_char* packet;		 // The actual packet
	struct iphdr* ipheader = NULL;   // Pointer to the IP header
	struct tcphdr* tcpheader = NULL; // Pointer to the TCP header
	char* field  = NULL;		 // Pointer to field begin
	int iphdr_size, packet_size, tcphdr_size, htpkt_size;
	iphdr_size = packet_size = tcphdr_size = htpkt_size = 0;
	MYSQL* conn;

	device = NULL;
	memset(errbuf, 0, PCAP_ERRBUF_SIZE);
	memset(httpbuf, 0, MAX_HTTP_SIZE);
	int count;

	if ( !(conn = mysql_conn())) {
		fprintf(stderr, "Can't connect to MySQL server");
		exit(1);
	}
		

	device = pcap_lookupdev(errbuf);
	printf("Device: %s\n", device);
	printf("filter: %s\n", filter_exp);
	if (pcap_lookupnet(device, &net, &mask, errbuf) == -1) {
		fprintf(stderr, "Can't get netmask for device %s\n", device);
		net = 0;
		mask = 0;
	}

	handle = pcap_open_live(device, 2048, 0, 512, errbuf);
	// Compile filter for capture
	if (pcap_compile(handle, &fp, filter_exp, 0, net) == -1) {
		fprintf(stderr, "Couldn't parse filter %s: %s\n", filter_exp, pcap_geterr(handle));
		exit(1);
	}
	// Apply compiled filter
	if (pcap_setfilter(handle, &fp) == -1) {
		fprintf(stderr, "Couldn't install filter %s: %s\n", filter_exp, pcap_geterr(handle));
		exit(1);
	}
	count = 100;
	while (count) {
		// Try to get packet. If capture fail - try next.
		if ( (packet = pcap_next(handle, &header)) == NULL) {
        		fprintf(stderr, "ERROR: Error getting the packet\n", errbuf);
			continue;
		} else {
			// uncomment for debug) <------------------
			/*
			fprintf(stderr, "Packet captured\n");
			fprintf(stderr, "Timestamp:        %d.%d\n", header.ts.tv_sec, header.ts.tv_usec);
			*/
		}
			
		// Extract IP header
		ipheader = (struct iphdr *)(packet + ETH_HDR_SIZE);
		iphdr_size = ipheader->ihl * 4;
		packet_size = ntohs(ipheader->tot_len);
		
		// Print IP Header fields (uncomment for debug) 
		/*
		printf("IP header lengh:  %d\n", iphdr_size);
		printf("Packet size:      %d\n", packet_size);
		printf("TTL:              %d\n", ipheader->ttl);
                printf("Source IP:        %s\n", inet_ntoa( *(struct in_addr *) &ipheader->saddr));
                printf("Destination IP:   %s\n", inet_ntoa( *(struct in_addr *) &ipheader->daddr));
		*/
		// Extract TCP header
                tcpheader = (struct tcphdr *)(packet + ETH_HDR_SIZE + iphdr_size);
		tcphdr_size = tcpheader->doff * 4;
		
		// Print TCP Header fields (uncomment for debug) 
		/*
		printf("TCP header lengh: %d\n", tcphdr_size);
		printf("Source port:      %d\n", ntohs(tcpheader->source));
		printf("Destination port: %d\n", ntohs(tcpheader->dest));
		printf("Flags:            ");
		if (tcpheader->syn)
			printf("SYN ");
		if (tcpheader->ack)
                        printf("ACK ");
		if (tcpheader->fin)
                        printf("FYN ");
		printf("\n");
		printf("Window:           %d\n", ntohs(tcpheader->window));
		*/ 
		// Calculate HTTP packet's size 
		htpkt_size = packet_size - (iphdr_size + tcphdr_size);
		//printf("HTTP packet size: %d\n", htpkt_size);
		
		// Truncate it, if exceed MAX_HTTP_SIZE
		if (htpkt_size > MAX_HTTP_SIZE)
			htpkt_size = MAX_HTTP_SIZE;
		// Extract HTTP packet
                if (htpkt_size > 0) {	
			memset(httpbuf, 0, MAX_HTTP_SIZE);
			memcpy(httpbuf, packet + ETH_HDR_SIZE + iphdr_size + tcphdr_size, htpkt_size);
			// Request string
			if (strstr(httpbuf, "GET") || strstr(httpbuf, "PUT")) {
                                memset(request, 0, MAX_FIELD_SIZE);
				memccpy(request, httpbuf, '\n', MIN(MAX_REQ_SIZE,htpkt_size));
				//printf("Request string: %s", request);
			}
			// Host
			if ( (field = strstr(httpbuf, "Host:"))) {
                                memset(host, 0, MAX_FIELD_SIZE);
				memccpy(host, field + 6, '\n', MIN(MAX_FIELD_SIZE,htpkt_size - (field - httpbuf)));
				//printf("%s", host);
			}
			// User-Agent
			if ( (field = strstr(httpbuf, "User-Agent:"))) {
                                memset(useragent, 0, MAX_FIELD_SIZE);
                                memccpy(useragent, field + 12, '\n', MIN(MAX_FIELD_SIZE,htpkt_size - (field - httpbuf)));
                                //printf("%s", useragent);
                        }
			//printf("Entire HTTP packet:\n");
			//printf("%s\n", httpbuf);
		}
		//printf("\n");
		char* stat = "INSERT INTO header VALUES('%u', '%u', '%u', '%u', '%u', '%u', '%u', '%u', '%u', '%u',"
						       "'%u', '%u', '%u', '%u', '%u', '%s', '%s', '%s')";
			
		snprintf(query, 2048, stat, header.ts.tv_sec, header.ts.tv_usec, iphdr_size, packet_size, ipheader->ttl,
			ntohl(ipheader->saddr), ntohl(ipheader->daddr), tcphdr_size, ntohs(tcpheader->source),
			ntohs(tcpheader->dest), tcpheader->syn, tcpheader->ack, tcpheader->fin, tcpheader->window,
			htpkt_size, request, host, useragent);
		//printf("%s\n", query);
		mysql_query(conn, query);
	}
	pcap_close(handle);
	mysql_close(conn);

	return 0;
}

MYSQL* mysql_conn() {
	
	MYSQL* conn;
        MYSQL_RES* res;
        MYSQL_ROW row;
        char* server = "localhost";
        char* user = "root";
        char* password = "password";
        char* database = "pget";

	conn = mysql_init(NULL);
	if (!mysql_real_connect(conn, server, user, password, database, 0, NULL, 0)) {
		fprintf(stderr, "%s\n", mysql_error(conn));
      		return NULL;
   	}
	return conn;
}
