#include <arpa/inet.h>
#include "ethernet_header.h"
#include "log_dump.h"

const char* dump_ether_type_str(const int _ether_type)
{
	switch(_ether_type)
	{
		case ETHER_TYPE_IP:
		{
			log_info("ipv4 \n");
			return "IPv4";
		}
		
		case ETHER_TYPE_ARP:
		{
			log_info("arp \n");
			return "ARP";
		}

		case ETHER_TYPE_LOOPBACK:
		{
			log_info("loopback \n");
			return "Loopback";
		}
		
		case ETHER_TYPE_IPV6:
		{
			log_info("ipv6 \n");
			return "IPv6";
		}

		default:
		{
			log_warning("_ether_type 0x%x not support\n", _ether_type);
			return "not support";
		}
	}		
	return "invalid";
}

const char* dump_ether_addr_str(const u_char* _ether_addr)
{
	log_info("%02x:%02x:%02x:%02x:%02x:%02x\n", _ether_addr[0], _ether_addr[1], _ether_addr[2], _ether_addr[3], _ether_addr[4], _ether_addr[5]);
	return "srt";
}

void dump_ether_header(const sniff_ethernet_t* _ether_hdr)
{
	if (!_ether_hdr)
	{
		return;	
	}	

	dump_ether_addr_str(_ether_hdr->ether_src_host);
	dump_ether_addr_str(_ether_hdr->ether_dst_host);	
	dump_ether_type_str(ntohs(_ether_hdr->ether_type));
}