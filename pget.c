#include "pget.h"
#include <sys/types.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <sys/file.h>

#include <pthread.h>
#define FILE_SIZE 3355443

void pget(u_char *args, const struct pcap_pkthdr *header, const u_char *packet);

MYSQL* conn;
MYSQL_RES *res;
char* data;
pthread_mutex_t mutex  = PTHREAD_MUTEX_INITIALIZER;



void inject_value(char* str, int value) {
        char  tmpbuf[16];                // Temporary buffer for conversion
        char  divider[] = "', '";          // Divide value in query

        memset(tmpbuf, 0, 16);

        snprintf(tmpbuf, 16, "%u", value);
        strcat(str, tmpbuf);        
        strcat(str, divider);
}

void* query_thread() {
        printf("query_thread start\n");
        conn = NULL;
        int status = 0;
        char* mirror;

        // MYSQL connect
        if ( !(conn = mysql_conn())) {
                fprintf(stderr, "Can't connect to MySQL server");
                exit(1);
        }
        
        mirror = malloc(FILE_SIZE);
        memset(mirror, 0, FILE_SIZE);
        while (1) {
                sleep(20);
                //************************************
                printf("query_thread: wait for critical\n");
                pthread_mutex_lock(&mutex);
                printf("query_thread: in critical\n");
                printf("query_thread: let strncpy to 0x%x from 0x%x\n", mirror, data);
                strncpy(mirror, data, FILE_SIZE);
                //data[0] = 0;
                memset(data, 0, FILE_SIZE);
                pthread_mutex_unlock(&mutex);
                printf("query_thread: out critical\n");
                //************************************

                if (strlen(mirror) > 0) {
                         mysql_query(conn, mirror);
                         do {   
                               res = mysql_store_result(conn);
                               if (res)
                                        mysql_free_result(res);
                                status = mysql_next_result(conn);
                         } while (status == 0);
                         memset(mirror, 0, FILE_SIZE);
                }
        }
}


void* pcap_thread() {
        printf("pcap_thread start");
        struct pcap_pkthdr header;       // The header that pcap gives us
        const u_char* packet;            // The actual packet
        char* device;                    // Sniffing device
        char errbuf[PCAP_ERRBUF_SIZE];   // Error message buffer
        pcap_t* handle;                  // Session handle
        struct bpf_program fp;           // The compiled filter expression
        char filter_exp[] = "dst port 80";
//      char filter_exp[] = "dst net 188.93.212.0/24 and not src net 188.93.208.0/21 and dst port 80";   // The filter expression
        bpf_u_int32 mask;                // The netmask of our sniffing device
        bpf_u_int32 net;                 // The IP of our sniffing device
        device = NULL;
        memset(errbuf, 0, PCAP_ERRBUF_SIZE);

                // Get device for capture
        device = pcap_lookupdev(errbuf);
        printf("Device: %s\n", device);
        printf("filter: %s\n", filter_exp);
        if (pcap_lookupnet(device, &net, &mask, errbuf) == -1) {
                fprintf(stderr, "Can't get netmask for device %s\n", device);
                net = 0;
                mask = 0;
        }

        handle = pcap_open_live(device, 1514, 0, 1, errbuf);
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
        pcap_loop(handle, 0, pget, NULL);

        pcap_close(handle);
}


void pget(u_char *args, const struct pcap_pkthdr *header, const u_char *packet) {

        char httpbuf[MAX_HTTP_SIZE];     // HTTP packet buffer
        char request[MAX_REQ_SIZE];      // Buffer for extract HTTP request
        char host[MAX_FIELD_SIZE];       // Buffer for extract HTTP Host
        char useragent[MAX_FIELD_SIZE];  // Buffer for extract HTTP User-Agent
        struct iphdr* ipheader = NULL;   // Pointer to the IP header
        struct tcphdr* tcpheader = NULL; // Pointer to the TCP header
        char* field  = NULL;             // Pointer to field begin
        int iphdr_size, packet_size, tcphdr_size, htpkt_size;
        iphdr_size = packet_size = tcphdr_size = htpkt_size = 0;
        memset(httpbuf, 0, MAX_HTTP_SIZE);
        // Query buffer
        char query[2048] = "INSERT INTO headers VALUES('";
        // Print timestamp
        /*
        fprintf(stderr, "Packet captured\n");
        fprintf(stderr, "Timestamp:        %d.%d\n", header->ts->tv_sec, header->ts->tv_usec);
        */
        // Append timestamp to query
        inject_value(query, header->ts.tv_sec);
        inject_value(query, header->ts.tv_usec);

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

        // Appent IP Header to query
        inject_value(query, (int)iphdr_size);
        inject_value(query, (int)packet_size);
        inject_value(query, (int)ipheader->ttl);
        inject_value(query, ntohl(ipheader->saddr));
        inject_value(query, ntohl(ipheader->daddr));

        // Extract TCP header
        tcpheader = (struct tcphdr *)(packet + ETH_HDR_SIZE + iphdr_size);
        tcphdr_size = tcpheader->doff * 4;

        // Calculate HTTP packet's size
        htpkt_size = packet_size - (iphdr_size + tcphdr_size);

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

        // Appent IP Header to query
        inject_value(query, (int)tcphdr_size);
        inject_value(query, (int)ntohs(tcpheader->source));
        inject_value(query, (int)ntohs(tcpheader->dest));
        inject_value(query, (int)tcpheader->syn);
        inject_value(query, (int)tcpheader->ack);
        inject_value(query, (int)tcpheader->fin);
        inject_value(query, (int)tcpheader->window);

        //printf("HTTP packet size: %d\n", htpkt_size);

        // Append HTTP packet lengh to query
        inject_value(query, (htpkt_size));

        // Extract HTTP packet
        if (htpkt_size > 0) {
                memset(httpbuf, 0, MAX_HTTP_SIZE);
                memcpy(httpbuf, packet + ETH_HDR_SIZE + iphdr_size + tcphdr_size, htpkt_size);

                // Request string
                if (strstr(httpbuf, "GET") || strstr(httpbuf, "PUT")) {
                        memset(request, 0, MAX_FIELD_SIZE);
                        memccpy(request, httpbuf, '\r', MIN(MAX_REQ_SIZE,htpkt_size));
                        request[strlen(request) - 1] = 0;
                        //printf("Request string: %s", request);
                        strcat(query, request);
                        strcat(query, "', '");
                }
                // Host
                if ( (field = strstr(httpbuf, "Host:"))) {
                        memset(host, 0, MAX_FIELD_SIZE);
                        memccpy(host, field + 6, '\r', MIN(MAX_FIELD_SIZE,htpkt_size - (field - httpbuf)));
                        host[strlen(host) - 1] = 0;
                        //printf("%s", host);
                        strcat(query, host);
                        strcat(query, "', '");

                }
                // User-Agent
                if ( (field = strstr(httpbuf, "User-Agent:"))) {
                        memset(useragent, 0, MAX_FIELD_SIZE);
                        memccpy(useragent, field + 12, '\r', MIN(MAX_FIELD_SIZE,htpkt_size - (field - httpbuf)));
                        useragent[strlen(useragent) - 1] = 0;
                        //printf("%s", useragent);
                        strcat(query, useragent);
                        strcat(query, "');");
                }
                // Print HTTP packet
                /*
                printf("Entire HTTP packet:\n");
                printf("%s\n", httpbuf);
                */
        } else {
                query[strlen(query) - 1] = 0;
                strcat(query, "NULL, NULL, NULL);"); 
        }
        // Send INSERT query
        //************************************
        printf("pcap_thread: wait for critical\n");
        pthread_mutex_lock(&mutex);
        printf("pcap_thread: in critical\n");
        strcat(data, query);
        strcat(data, "\n");
        pthread_mutex_unlock(&mutex);
        printf("pcap_thread: out critical\n");
        //************************************
}


int main() {
        pthread_t pcthread, qthread;
        data =  mmap(NULL, FILE_SIZE, PROT_READ | PROT_WRITE, MAP_ANONYMOUS | MAP_SHARED, 0, 0);
        memset(data, 0, FILE_SIZE);
        int pc_ret, q_ret;

        pc_ret = pthread_create(&pcthread, NULL, pcap_thread, NULL);
        q_ret  = pthread_create(&qthread, NULL, query_thread, NULL);
        
        pthread_join(pcthread, NULL);
        pthread_join(qthread, NULL);

        mysql_close(conn);

        return 0;
}

MYSQL* mysql_conn() {

        MYSQL* connect = NULL;
        char* server = "speedcorezombie.net";
        char* user = "root";
        char* password = "yeyzfz20";
        char* database = "pget";

        connect = mysql_init(NULL);
        if (!mysql_real_connect(connect, server, user, password, database, 0, NULL, CLIENT_MULTI_STATEMENTS)) {
                fprintf(stderr, "%s\n", mysql_error(connect));
                return NULL;
        }
        return connect;
}
