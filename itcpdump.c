#include <stdio.h>
#include <stdlib.h>
#include <pcap/pcap.h>
#include <errno.h>
#include <sys/socket.h>
#include <stdarg.h>
#include <netinet/in.h>
#include <arpa/inet.h>

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
	return 0;
}