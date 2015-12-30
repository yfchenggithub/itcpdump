#ifndef IP_HDR_H
#define IP_HDR_H

#include <sys/types.h> /*define u_char*/
#include <arpa/inet.h> /*define struct in_addr*/

/*ip header*/
typedef struct _sniff_ip
{
	u_char ip_vhl; /*version 4 bits and header length 4 bits*/
	u_char ip_tos; /*type of service*/
	u_short ip_len; /*header and payload sum*/
	u_short ip_id; /*identification; the only identification*/
	u_short ip_off; /*fragment offset field*/
	#define IP_RF 0x8000; /* reserved fragment flag */
	#define IP_DF 0x4000; /*dont fragment flag*/
	#define IP_MF 0x2000; /*more fragments flag*/
	#define IP_OFFMASK 0x1fff; /*mask for fragmenting bits*/
	u_char ip_ttl; /*time to live*/
	u_char ip_proto; /*protocol*/
	u_short ip_sum; /*checksum*/
	struct in_addr ip_src; /*source address*/
	struct in_addr ip_dst; /*dest address*/

}sniff_ip_t;

#define IP_HL(ip)  (((ip)->ip_vhl) & 0x0f)
#define IP_V(ip)   (((ip)->ip_vhl) >> 4)

#ifndef IPPROTO_TCP
#define IPPROTO_TCP 6
#endif

#ifndef IPPROTO_UDP
#define IPPROTO_UDP 17
#endif

#ifndef IPPROTO_ICMP
#define IPPROTO_ICMP 1
#endif

char* in_addr_to_str(struct in_addr _addr);
void dump_ip_proto_str(u_char _ip_proto);
void dump_ip_hdr(const sniff_ip_t* _ip_hdr);
#endif
