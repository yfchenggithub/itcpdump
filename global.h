#ifndef GLOBAL_H
#define GLOBAL_H

typedef enum BOOL
{
	false = 0,
	true = 1,
}bool;

extern bool pkt_link_ethernet;
extern bool pkt_arp;
extern bool pkt_rarp;
extern bool pkt_network_ip;
extern bool pkt_icmp;
extern bool pkt_transport_tcp;
extern bool pkt_transport_udp;

extern inline void set_pkt_arp_flag(bool _flag);
extern inline bool get_pkt_arp_flag();
extern inline bool get_pkt_link_ethernet_flag();
extern inline void set_pkt_icmp_flag(bool _flag);
extern inline bool get_pkt_icmp_flag(); 
extern inline void set_pkt_ethernet_link(bool _flag);
extern inline bool get_pkt_network_ip_flag();
extern inline void set_pkt_network_ip_flag(bool _flag);
extern inline bool get_pkt_transport_tcp_flag();
extern inline void set_pkt_transport_tcp_flag(bool _flag);
extern inline bool get_pkt_transport_udp_flag();
extern inline void set_pkt_transport_udp_flag(bool _flag);

#endif
