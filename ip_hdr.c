#include <string.h>
#include <strings.h>
#include "ip_hdr.h"
#include "log_dump.h"
#include "global.h"

#define IP_STR_MAX_SIZE 20
char* in_addr_to_str(struct in_addr _addr)
{
	static char _addr_str[IP_STR_MAX_SIZE + 1];
	bzero(_addr_str, sizeof(_addr_str));
	
	char* _tmp = inet_ntoa(_addr);
	strncpy(_addr_str, _tmp, IP_STR_MAX_SIZE);
	return _addr_str;
}

void dump_ip_proto_str(u_char _ip_proto)
{
	switch (_ip_proto)
	{
		log_info("protocol: ");
		case IPPROTO_TCP:
			log_info("tcp ");
			set_pkt_tcp_transport(true);	
			break;
		case IPPROTO_UDP:
			log_info("udp ");
			set_pkt_udp_transport(true);
			break;
		case IPPROTO_ICMP:
			log_info("icmp ");
			set_pkt_icmp_flag(true);	
			break;
		default:
			log_warning("_ip_proto %d not support\n", _ip_proto);
	}
}

void dump_ip_hdr(const sniff_ip_t* _ip_hdr)
{
	if (!_ip_hdr)
	{
		return;
	}

	u_char _ip_version = IP_V(_ip_hdr);
	log_info("_ip_version %d ", _ip_version);
	
	u_short _ip_hdr_len = IP_HL(_ip_hdr) * 4;
	log_info("_ip_hdr_len %d ", _ip_hdr_len);
	
	u_char _ip_tos_type = _ip_hdr->ip_tos;
	log_info("_ip_tos_type 0x%x ", _ip_tos_type);
	
	u_short _ip_total_len = ntohs(_ip_hdr->ip_len);
	log_info("_ip_total_len %d ", _ip_total_len);
	
	u_short _ip_id = ntohs(_ip_hdr->ip_id);
	log_info("_ip_id %d ", _ip_id);
	
	u_short _ip_offset = ntohs(_ip_hdr->ip_off);
	log_info("_ip_offset %d ", _ip_offset & 0x1fff);
	
	u_char _ip_flag = (_ip_offset & 0xe000) >> 13;
	log_info("_ip_flag 0x%x ", _ip_flag);	

	u_char _ip_ttl = _ip_hdr->ip_ttl;
	log_info("_ip_ttl %d ", _ip_ttl);
	
	dump_ip_proto_str(_ip_hdr->ip_proto);
	
	u_short _ip_checksum = ntohs(_ip_hdr->ip_sum);
	log_info("_ip_checksum 0x%x ", _ip_checksum);
	
	log_info("src addr: %s ", in_addr_to_str(_ip_hdr->ip_src));
	log_info("dst addr: %s ", in_addr_to_str(_ip_hdr->ip_dst));	
	log_info("\n");
}
