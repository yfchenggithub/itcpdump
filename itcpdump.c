#include <stdio.h>
#include <stdlib.h>
#include <pcap/pcap.h>
#include <errno.h>
#include <sys/socket.h>
#include <stdarg.h>
#include <netinet/in.h>
#include <netinet/ether.h>
#include <netinet/if_ether.h>
#include <arpa/inet.h>
#include <net/ethernet.h>

void log_error(const char* fmt, ...)
{
	va_list va;
	va_start(va, fmt);
	vprintf(fmt, va);	
	va_end(va);	
}

void log_info(const char* fmt, ...)
{
	va_list va;
	va_start(va, fmt);
	vprintf(fmt, va);	
	va_end(va);	
}

void log_debug(const char* fmt, ...)
{
	va_list va;
	va_start(va, fmt);
	vprintf(fmt, va);	
	va_end(va);	
}

void log_warning(const char* fmt, ...)
{
	va_list va;
	va_start(va, fmt);
	vprintf(fmt, va);	
	va_end(va);	
}

/*callback is passed to pcap_loop, called each time a packet received*/
void my_callback(u_char* useless, const struct pcap_pkthdr* pkthdr, const u_char* packet)
{
	static int _pkt_total = 0;
	log_info("capture %d packets\n", _pkt_total);
	fflush(stdout);		
	++_pkt_total;
}

int main(int argc, char** argv)
{
	char _errbuf[PCAP_ERRBUF_SIZE];
	char* _dev = pcap_lookupdev(_errbuf);
	if (!_dev)
	{
		log_error("pcap_lookupdev null, %s\n",_errbuf);	
		return -1;
	}
	log_info("lookup dev: %s\n", _dev);	
	
	bpf_u_int32 _net, _mask;
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
	
	pcap_t* _pd = pcap_open_live(_dev, 65535, 1, 1000, _errbuf);
	if (!_pd)
	{
		log_error("pcap_open_live %s fail: %s\n", _dev, _errbuf);
		return -1;
	}

	struct bpf_program _bpf;
	
	if (argv[1])
	{	
		if (pcap_compile(_pd, &_bpf, argv[1], 0, _net) < 0)
		{
			log_error("pcap_compile fail: %s\n", _errbuf);
			return -1;
		}

		if (pcap_setfilter(_pd, &_bpf) < 0)
		{
			log_error("pcap_setfilter fail: %s\n", _errbuf);
			return -1;
		}
	}	
	pcap_loop(_pd, 0, my_callback, NULL);
	return 0;
}
