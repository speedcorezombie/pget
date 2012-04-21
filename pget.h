// In CentOS <pcap.h>, in Fedora <pcap/pcap.h>
#include <pcap/pcap.h>
//#include <pcap.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <stdlib.h>
#include <string.h>
#include <mysql.h>
#include <sys/types.h>
#include <sys/mman.h>
#include <pthread.h>

#define MAX_HTTP_SIZE 1460               // Max allowed HTTP packet size
#define MAX_FIELD_SIZE 92               // Max allowed field size in HTTP header
#define MAX_REQ_SIZE 128                 // Max allowed request string size
#define ETH_HDR_SIZE 14                  // Ethernet header size
#define MIN(X,Y) ((X) < (Y) ? (X) : (Y))
#define FILE_SIZE 33554430
#define QUERY_SIZE 512

MYSQL* mysql_conn();
void pget(u_char *args, const struct pcap_pkthdr *header, const u_char *packet);

MYSQL* conn;
MYSQL_RES *res;
char* data;
