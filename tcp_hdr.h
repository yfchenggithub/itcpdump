#ifndef TCP_HDR_H
#define TCP_HDR_H

#include <sys/types.h>

typedef struct _sniff_tcp_hdr
{
	u_short src_port; /*source port*/
	u_short dst_port; /*destination port*/
	u_int seq_id; /*sequence number*/
	u_int ack_id; /*acknowledgement number*/
	u_char th_offx2; /*data offset, rsvd*/
	u_char th_flags; /*syn fin ack*/
	#define TH_OFF(th) ((((th)->th_offx2) & 0xf0) >> 4)
	#define TH_FIN 0x01
	#define TH_SYN 0x02
	#define TH_RST 0x04
	#define TH_PUSH 0x08
	#define TH_ACK 0x10
	#define TH_URG 0x20
	#define TH_ECE 0x40
	#define TH_CWR 0x80
	#define TH_FLAGS (TH_FIN|TH_SYN|TH_RST|TH_PUSH|TH_ACK|TH_URG|TH_ECE|TH_CWR)
	u_short th_win; /*window */
	u_short th_sum; /* checksum  */
	u_short th_urp; /* urgent pointer */

}sniff_tcp_hdr_t;

void dump_tcp_flags_str(u_short _tcp_flag);
void dump_tcp_hdr(const sniff_tcp_hdr_t* _tcp_hdr);
#endif
