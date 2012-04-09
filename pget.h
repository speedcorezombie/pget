#include <pcap/pcap.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <stdlib.h>
#include <string.h>
#include <mysql.h>

#define MAX_HTTP_SIZE 2048               // Max allowed HTTP packet size
#define MAX_FIELD_SIZE 128               // Max allowed field size in HTTP header
#define MAX_REQ_SIZE 192                 // Max allowed request string size
#define ETH_HDR_SIZE 14                  // Ethernet header size
#define MIN(X,Y) ((X) < (Y) ? (X) : (Y))

MYSQL* mysql_conn();
