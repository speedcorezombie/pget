#include <pcap/pcap.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>
#include <netinet/in.h>

int main() {

	char* device;                    // Sniffing device
	char errbuf[PCAP_ERRBUF_SIZE];   // Error message buffer
	char httpbuf[512];
	pcap_t* handle;                  // Session handle
	struct bpf_program fp;           // The compiled filter expression
	char filter_exp[] = "port 80";   // The filter expression
	bpf_u_int32 mask;                // The netmask of our sniffing device
	bpf_u_int32 net;                 // The IP of our sniffing device
	struct pcap_pkthdr header;       // The header that pcap gives us
	const u_char* packet;		 // The actual packet
	struct iphdr* ipheader = NULL;   // Pointer to the IP header
	struct tcphdr* tcpheader = NULL; // Pointer to the TCP header
	int iphdr_size, packet_size, tcphdr_size;
	iphdr_size = packet_size = tcphdr_size = 0;
	device = NULL;
	memset(errbuf, 0, PCAP_ERRBUF_SIZE);
	memset(httpbuf, 0, 512);
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

	if (pcap_compile(handle, &fp, filter_exp, 0, net) == -1) {
		fprintf(stderr, "Couldn't parse filter %s: %s\n", filter_exp, pcap_geterr(handle));
		exit(1);
	}

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
		ipheader = (struct iphdr *)(packet + 14);
		iphdr_size = ipheader->ihl * 4;
		packet_size = ntohs(ipheader->tot_len);
		printf("IP header lengh:  %d\n", iphdr_size);
		printf("Packet size:  %d\n", packet_size);
                printf("Source IP:        %s\n", inet_ntoa( *(struct in_addr *) &ipheader->saddr));
                printf("Destination IP:   %s\n", inet_ntoa( *(struct in_addr *) &ipheader->daddr));
		// Extract TCP header
                tcpheader = (struct tcphdr *)(packet + 14 + iphdr_size);
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
		memcpy(httpbuf, packet + 14 + iphdr_size + tcphdr_size, packet_size - (iphdr_size + tcphdr_size));
		printf("%s\n", httpbuf);
        	memset(httpbuf, 0, 512);
		printf("\n");

	}
	pcap_close(handle);
	return 0;
} 
