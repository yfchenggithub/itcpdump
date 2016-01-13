#include <arpa/inet.h>
#include "icmp_hdr.h"
#include "log_dump.h"

void dump_icmp_type(uint8_t _type)
{
	log_info("type: %d ", _type);	
}

void dump_icmp_code(uint8_t _code)
{
	log_info("code: %d ", _code);
}

void dump_icmp_hdr(const sniff_icmp_hdr_t* _icmp_hdr)
{
	if (!_icmp_hdr)
	{
		return;
	}

	dump_icmp_type(_icmp_hdr->icmp_type);
	dump_icmp_code(_icmp_hdr->icmp_code);
	
	uint16_t _cksum = ntohs(_icmp_hdr->icmp_cksum);
	log_info("cksum: 0x%x ", _cksum);		
	
	log_info("\n");
}
