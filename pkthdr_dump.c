#include <stdio.h>
#include <pcap/pcap.h>
#include "log_dump.h"
/*
struct pcap_pkthdr {
	struct timeval ts;	 time stamp 
	bpf_u_int32 caplen;	 length of portion present
	bpf_u_int32 len;	 length this packet (off wire)
};
*/

void dump_pkthdr(const struct pcap_pkthdr* _pkthdr)
{
	if (!_pkthdr)
	{
		return;
	}
		
	log_info("caplen %d\n", _pkthdr->caplen);
	log_info("len %d\n", _pkthdr->len);
}
