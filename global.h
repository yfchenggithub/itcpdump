#ifndef GLOBAL_H
#define GLOBAL_H

typedef enum BOOL
{
	false = 0,
	true = 1,
}bool;

extern bool pkt_ethernet_link;
extern bool pkt_arp;
extern bool pkt_rarp;
extern bool pkt_ip_network;
extern bool pkt_icmp;
extern bool pkt_tcp_transport;
extern bool pkt_udp_transport;

extern inline bool get_pkt_ethernet_link();
extern inline void set_pkt_icmp_flag(bool _flag);
extern inline bool get_pkt_icmp(); 
extern inline void set_pkt_ethernet_link(bool _flag);
extern inline bool get_pkt_ip_network();
extern inline void set_pkt_ip_network(bool _flag);
extern inline bool get_pkt_tcp_transport();
extern inline void set_pkt_tcp_transport(bool _flag);
extern inline bool get_pkt_udp_transport();
extern inline void set_pkt_udp_transport(bool _flag);

#endif
