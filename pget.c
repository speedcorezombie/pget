#include <pcap/pcap.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>
#include <netinet/in.h>

#define MAX_HTTP_SIZE 2048 		 // Max allowed HTTP packet size
#define MAX_FIELD_SIZE 2048               // Max allowed field size in HTTP header
#define ETH_HDR_SIZE 14			 // Ethernet header size

int main() {

	char* device;                    // Sniffing device
	char errbuf[PCAP_ERRBUF_SIZE];   // Error message buffer
	char httpbuf[MAX_HTTP_SIZE];     // HTTP packet buffer
	char buf[MAX_FIELD_SIZE];        // Buffer for extract HTTP headers
	pcap_t* handle;                  // Session handle
	struct bpf_program fp;           // The compiled filter expression
	char filter_exp[] = "port 80";   // The filter expression
	bpf_u_int32 mask;                // The netmask of our sniffing device
	bpf_u_int32 net;                 // The IP of our sniffing device
	struct pcap_pkthdr header;       // The header that pcap gives us
	const u_char* packet;		 // The actual packet
	struct iphdr* ipheader = NULL;   // Pointer to the IP header
	struct tcphdr* tcpheader = NULL; // Pointer to the TCP header
	char* field  = NULL;		 // Pointer to field begin
	int iphdr_size, packet_size, tcphdr_size, htpkt_size;
	iphdr_size = packet_size = tcphdr_size = htpkt_size = 0;
	
	device = NULL;
	memset(errbuf, 0, PCAP_ERRBUF_SIZE);
	memset(httpbuf, 0, MAX_HTTP_SIZE);
	int count;

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
		} else
			fprintf(stderr, "Packet captured\n");
		
		// Extract IP header
		ipheader = (struct iphdr *)(packet + ETH_HDR_SIZE);
		iphdr_size = ipheader->ihl * 4;
		packet_size = ntohs(ipheader->tot_len);
		printf("IP header lengh:  %d\n", iphdr_size);
		printf("Packet size:      %d\n", packet_size);
                printf("Source IP:        %s\n", inet_ntoa( *(struct in_addr *) &ipheader->saddr));
                printf("Destination IP:   %s\n", inet_ntoa( *(struct in_addr *) &ipheader->daddr));
		// Extract TCP header
                tcpheader = (struct tcphdr *)(packet + ETH_HDR_SIZE + iphdr_size);
		tcphdr_size = tcpheader->doff * 4;
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

		// Calculate HTTP packet's size 
		htpkt_size = packet_size - (iphdr_size + tcphdr_size);
		printf("HTTP packet size: %d\n", htpkt_size);

		// Truncate it, if exceed MAX_HTTP_SIZE
		if (htpkt_size > MAX_HTTP_SIZE)
			htpkt_size = MAX_HTTP_SIZE;
		// Extract HTTP packet
                if (htpkt_size > 0) {	
			memset(httpbuf, 0, MAX_HTTP_SIZE);
			memcpy(httpbuf, packet + ETH_HDR_SIZE + iphdr_size + tcphdr_size, htpkt_size);
			// Request string
			if (strstr(httpbuf, "GET") || strstr(httpbuf, "PUT")) {
				memccpy(buf, httpbuf, '\n', htpkt_size);
				printf("Request string: %s", buf);
				memset(buf, 0, MAX_FIELD_SIZE);
			}
			// Host
			if ( (field = strstr(httpbuf, "Host:"))) {
				memccpy(buf, field, '\n', htpkt_size - (field - httpbuf));
				printf("%s", buf);
				memset(buf, 0, MAX_FIELD_SIZE);
			}
			// User-Agent
			if ( (field = strstr(httpbuf, "User-Agent:"))) {
                                memccpy(buf, field, '\n', htpkt_size - (field - httpbuf));
                                printf("%s", buf);
				memset(buf, 0, MAX_FIELD_SIZE);
                        }
			printf("Entire HTTP packet:\n");
			printf("%s\n", httpbuf);
		}
		printf("\n");
	}
	pcap_close(handle);
	return 0;
} 
