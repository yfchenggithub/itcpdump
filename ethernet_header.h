
#ifndef ETHERNET_HEADER_H
#define ETHERNET_HEADER_H

#include <sys/types.h> /*u_char define*/

/*Ethernet address 6 bytes*/
#define M_ETHER_ADDR_LEN 6

/*Ethernet header*/
typedef struct _sniff_ethernet
{
	u_char ether_dst_host[M_ETHER_ADDR_LEN]; /*Destination host address*/
	u_char ether_src_host[M_ETHER_ADDR_LEN]; /*Source host address*/
	u_short ether_type; /*IP? ARP? RARP? etc*/
}sniff_ethernet_t;

#define M_ETHER_HDR_LEN 14

typedef enum ETHER_TYPE
{
	ETHER_TYPE_INVALID = -1,
	ETHER_TYPE_IP = 0x0800,
	ETHER_TYPE_ARP = 0x0806,
	ETHER_TYPE_LOOPBACK = 0x9000,
	ETHER_TYPE_IPV6 = 0x86dd,
}ETHER_TYPE_T;

const char* dump_ether_type_str(const int _ether_type);
const char* dump_ether_addr_str(const u_char* _ether_addr);
void dump_ether_header(const sniff_ethernet_t* _ether_hdr);

#endif
