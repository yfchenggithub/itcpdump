/*
 struct pcap_pkthdr {
	struct timeval ts;	 time stamp 
	bpf_u_int32 caplen;	 length of portion present 
	bpf_u_int32 len;	 length this packet (off wire) 
};
*/

void dump_pkthdr(const struct pcap_pkthdr* _pkthdr);
