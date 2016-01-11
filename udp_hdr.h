#ifndef UDP_HDR_H
#define UDP_HDR_H

#include <sys/types.h>

typedef struct _sniff_udp_hdr
{
	u_short uh_src_port; /*source port*/
	u_short uh_dst_port; /*destination port*/
	u_short uh_len; /*header + data*/
	u_short uh_checksum; /*include header and data*/
}sniff_udp_hdr_t;

void dump_udp_hdr(const sniff_udp_hdr_t* _udp_hdr);
#endif

