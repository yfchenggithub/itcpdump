#include <sys/types.h>
#include "global.h"

bool pkt_link_ethernet = false;
bool pkt_arp = false;
bool pkt_rarp = false;
bool pkt_network_ip = false;
bool pkt_icmp = false;
bool pkt_transport_tcp = false;
bool pkt_transport_udp = false;

inline bool get_pkt_arp_flag()
{
	return pkt_arp;
}

inline void set_pkt_arp_flag(bool _flag)
{
	pkt_arp = _flag;
}

inline bool get_pkt_icmp_flag()
{
	return pkt_icmp;
}

inline void set_pkt_icmp_flag(bool _flag)
{
	pkt_icmp = _flag;
}

inline bool get_pkt_link_ethernet_flag()
{
	return pkt_link_ethernet;
}

inline void set_pkt_link_ethernet_flag(bool _flag)
{
	pkt_link_ethernet = _flag;
}

inline bool get_pkt_network_ip_flag()
{
	return pkt_network_ip;
}

inline void set_pkt_network_ip_flag(bool _flag)
{
	pkt_network_ip = _flag;
}

inline bool get_pkt_transport_tcp_flag()
{
	return pkt_transport_tcp;
}

inline void set_pkt_transport_tcp_flag(bool _flag)
{
	pkt_transport_tcp = _flag;
}

inline bool get_pkt_transport_udp_flag()
{
	return pkt_transport_udp;
}

inline void set_pkt_transport_udp_flag(bool _flag)
{
	pkt_transport_udp = _flag;
}
