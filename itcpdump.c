#include "log_dump.h"
#include "itcpdump.h"
#include "pkthdr_dump.h"
#include "ethernet_header.h"
#include "ip_hdr.h"
#include "tcp_hdr.h"
#include "udp_hdr.h"
#include "global.h"

/*callback is passed to pcap_loop, called each time a packet received*/
/*pkthdr: information about when the packet was sniffed, how large it is*/
void got_packet_callback(u_char* _pcap_loop_last_arg, const struct pcap_pkthdr* pkthdr, const u_char* packet)
{
	static int _pkt_total = 0;
	const sniff_ethernet_t* _ethernet = (const sniff_ethernet_t*)packet;
	dump_ether_header(_ethernet);

	if (get_pkt_ip_network())
	{
		const sniff_ip_t* _ip_hdr = (const sniff_ip_t*)(packet + M_ETHER_HDR_LEN);
		dump_ip_hdr(_ip_hdr);
	}	

	if (get_pkt_tcp_transport())
	{
		size_t _ip_hdr_size = sizeof(sniff_ip_t);
		const sniff_tcp_hdr_t* _tcp_hdr = (const sniff_tcp_hdr_t*)(packet + M_ETHER_HDR_LEN + _ip_hdr_size);
		dump_tcp_hdr(_tcp_hdr);
	}
	
	if (get_pkt_udp_transport())
	{
		size_t _ip_hdr_size = sizeof(sniff_ip_t);
		const sniff_udp_hdr_t* _udp_hdr = (const sniff_udp_hdr_t*)(packet + M_ETHER_HDR_LEN + _ip_hdr_size);
		dump_udp_hdr(_udp_hdr);
	}

	fflush(stdout);		
	log_info("\n\n");
	++_pkt_total;
}

int main(int argc, char** argv)
{
	char _errbuf[PCAP_ERRBUF_SIZE + 1];
	bzero(_errbuf, sizeof(_errbuf));

	char* _dev = pcap_lookupdev(_errbuf);
	if (!_dev)
	{
		log_error("pcap_lookupdev null, %s\n",_errbuf);	
		return -1;
	}
	log_info("lookup dev: %s\n", _dev);	
	
	bpf_u_int32 _net, _mask;
	/*get network address and network mask for a capture device*/
	if (pcap_lookupnet(_dev, &_net, &_mask, _errbuf) < 0)
	{
		log_error("pcap_lookupnet error: %s\n", _errbuf);
		return -1;
	}
	
	struct in_addr _addr;
	_addr.s_addr = _net;
	char* _netp = inet_ntoa(_addr);
	if (!_netp)
	{
		log_error("inet_ntoa fail: %s\n", _errbuf);
		return -1;
	}
	log_info("net %s\n", _netp);
	
	_addr.s_addr = _mask;
	char* _maskp = inet_ntoa(_addr);
	log_info("mask %s\n", _maskp);
	
	int _snaplen = 65535;
	int _promisc_mode = 1;
	/*1秒(s) = 1000 毫秒(ms) = 1,000,000 微秒*/
	int _to_ms = 1000;
	pcap_t* _pd = pcap_open_live(_dev, _snaplen, _promisc_mode, _to_ms, _errbuf);
	if (!_pd)
	{
		log_error("pcap_open_live %s fail: %s\n", _dev, _errbuf);
		return -1;
	}

	log_info("opening device %s\n", _dev);
	struct bpf_program _bpf;
	const char* _filter_condition = argv[1];	
	if (_filter_condition)
	{	
		log_info("_filter_condition %s\n", _filter_condition);
		int _compile_optimize = 0;
		char* _tmp_err_msg = NULL;
		if (pcap_compile(_pd, &_bpf, _filter_condition, _compile_optimize, _net) < 0)
		{
			_tmp_err_msg = pcap_geterr(_pd);
			log_error("%s\n", _tmp_err_msg);
			return -1;
		}

		if (pcap_setfilter(_pd, &_bpf) < 0)
		{
			_tmp_err_msg = pcap_geterr(_pd);
			log_error("%s\n", _tmp_err_msg);
			return -1;
		}
	}	

	int _pkt_to_capture = 0; 
	if (argv[2])
	{
		_pkt_to_capture = atoi(argv[2]);
		log_info("_pkt_to_capture %d\n", _pkt_to_capture);
	}

	/*0 for cnt is equivalent to infinity*/
	u_char* _user_use_msg = (u_char*)"user use msg";
	int _loop_ret = pcap_loop(_pd, _pkt_to_capture, got_packet_callback, _user_use_msg);
	if (-1 == _loop_ret)
	{
		log_error("pcap_loop error\n");
	}
	
	if (-2 == _loop_ret)
	{
		log_error("called pcap_breakloop\n");
	}

	return 0;
}
