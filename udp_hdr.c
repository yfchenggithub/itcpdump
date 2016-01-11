#include <arpa/inet.h>
#include "udp_hdr.h"
#include "log_dump.h"

void dump_udp_hdr(const sniff_udp_hdr_t* _udp_hdr)
{
	if (!_udp_hdr)
	{
		return;
	}	
	
	u_short _src_port = ntohs(_udp_hdr->uh_src_port);
	log_info("_src_port: %d ", _src_port);
	
	u_short _dst_port = ntohs(_udp_hdr->uh_dst_port);
	log_info("_dst_port: %d ", _dst_port);
	
	u_short _header_and_data_len = ntohs(_udp_hdr->uh_len);
	log_info("_len: %d ", _header_and_data_len);
	
	u_short _checksum = ntohs(_udp_hdr->uh_checksum);
	log_info("_checksum: 0x%x ", _checksum); 		
	log_info("\n");
}
