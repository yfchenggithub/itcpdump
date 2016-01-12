#ifndef ARP_HDR_H
#define ARP_HDR_H
#include <sys/types.h>

/*Address Resolution Protocol.*/
typedef struct _sniff_arp_hdr
{
	u_short ar_hdr_type; /*format of hardware address*/
	u_short ar_pro_type; /*format of protocol address*/
	u_char ar_hdr_len; /*length of hardware address*/
	u_char ar_pro_len; /*length of protocol address*/
	u_short ar_op_type;/*arp/rarp request; arp/rarp reply*/
	#define ARPOP_REQUEST 1
	#define ARPOP_REPLY 2
	#define ARPOP_REVERSE_REQUEST 3
	#define ARPOP_REVERSE_REPLY 4	
}sniff_arp_hdr_t;

void dump_arp_hdr_info(const sniff_arp_hdr_t* _arp_hdr);
void dump_arp_hdr_addr(const u_char* _hdr_addr);
void dump_arp_ip_addr(const u_char* _ip_addr);
void dump_arp_operation_type(u_short _operation);
#endif
