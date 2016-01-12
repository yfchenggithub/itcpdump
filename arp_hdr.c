#include <arpa/inet.h>
#include "arp_hdr.h"
#include "log_dump.h"


static const char* g_arp_op_str[] = {"ARPOP_REQUEST", "ARPOP_REPLY", "ARPOP_REVERSE_REQUEST", "ARPOP_REVERSE_REPLY"};

void dump_arp_hdr_addr(const u_char* _hdr_addr)
{
	log_info("%02x:%02x:%02x:%02x:%02x:%02x  ", _hdr_addr[0], _hdr_addr[1], _hdr_addr[2], _hdr_addr[3], _hdr_addr[4], _hdr_addr[5]);	
}

void dump_arp_ip_addr(const u_char* _ip_addr)
{
	log_info("%d.%d.%d.%d ", (u_short)_ip_addr[0], (u_short)_ip_addr[1], (u_short)_ip_addr[2], (u_short)_ip_addr[3]);
}

void dump_arp_operation_type(u_short _operation)
{
	const char* _op_str = g_arp_op_str[_operation - 1];
	log_info("op_type: %s ", _op_str);		
}

void dump_arp_hdr_info(const sniff_arp_hdr_t* _arp_hdr)
{
	if (!_arp_hdr)
	{
		return;
	}
	
	u_short _hdr_type = ntohs(_arp_hdr->ar_hdr_type);
	log_info("_hdr_type: 0x%x ", _hdr_type);
	
	u_short _pro_type = ntohs(_arp_hdr->ar_pro_type);
	log_info("_pro_type 0x%04x ", _pro_type);
	
	/*ntohs at least two bytes*/	
	u_char _hdr_len = (_arp_hdr->ar_hdr_len);
	log_info("_hdr_len %d ", _hdr_len);
	
	u_char _pro_len = (_arp_hdr->ar_pro_len);
	log_info("_pro_len %d ", _pro_len);
	
	u_short _operation_type = ntohs(_arp_hdr->ar_op_type);
	dump_arp_operation_type(_operation_type);		
	
	log_info("send mac: ");	
	dump_arp_hdr_addr((const u_char*)((u_char*)_arp_hdr + 8));
	
	log_info("send ip: ");
	dump_arp_ip_addr((const u_char*)((u_char*)_arp_hdr + 14));
	
	log_info("dst mac: ");
	dump_arp_hdr_addr((const u_char*)((u_char*)_arp_hdr + 18));
	
	log_info("dst ip: ");
	dump_arp_ip_addr((const u_char*)((u_char*)_arp_hdr + 24));

	log_info("\n");
}
