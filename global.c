#include <sys/types.h>
#include "global.h"

bool pkt_ethernet_link = 0;
bool pkt_arp = 0;
bool pkt_rarp = 0;
bool pkt_ip_network = 0;
bool pkt_icmp = 0;
bool pkt_tcp_transport = 0;
bool pkt_udp_transport = 0;

inline bool get_pkt_icmp()
{
	return pkt_icmp;
}

inline void set_pkt_icmp_flag(bool _flag)
{
	pkt_icmp = _flag;
}

inline bool get_pkt_ethernet_link()
{
	return pkt_ethernet_link;
}

inline void set_pkt_ethernet_link(bool _flag)
{
	pkt_ethernet_link = _flag;
}

inline bool get_pkt_ip_network()
{
	return pkt_ip_network;
}

inline void set_pkt_ip_network(bool _flag)
{
	pkt_ip_network = _flag;
}

inline bool get_pkt_tcp_transport()
{
	return pkt_tcp_transport;
}

inline void set_pkt_tcp_transport(bool _flag)
{
	pkt_tcp_transport = _flag;
}

inline bool get_pkt_udp_transport()
{
	return pkt_udp_transport;
}

inline void set_pkt_udp_transport(bool _flag)
{
	pkt_udp_transport = _flag;
}
