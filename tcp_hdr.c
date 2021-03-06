#include <arpa/inet.h>
#include "tcp_hdr.h"
#include "log_dump.h"

#define NULL 0
static const char* tcp_flags_strs[] = {"FIN", "SYN", "RST", "PSH", "ACK", "URG", "ECE", "CWR", NULL};
static const int tcp_flags_ids[] = {0x1, 0x2, 0x4, 0x8, 0x10, 0x20, 0x40, 0x80, 0x0};

static int index_flags(u_char _flag)
{
	int _index = -1;
	while (_flag)
	{
		_flag = _flag >> 1;
		++_index;
	}
	return _index;
}

void dump_tcp_flags(u_char _tcp_flags)
{
	int flags_count = sizeof(tcp_flags_ids) / sizeof(int);
	int i;
	for (i=0; i<flags_count; ++i)
	{
		if (_tcp_flags & tcp_flags_ids[i])
		{
			int _index = index_flags(tcp_flags_ids[i]);
			log_info("%s ", tcp_flags_strs[_index]);
		}	
	}	
}
	
void dump_tcp_hdr(const sniff_tcp_hdr_t* _tcp_hdr)
{
	if (!_tcp_hdr)
	{
		return;
	}
	
	u_short _src_port = ntohs(_tcp_hdr->src_port);
	log_info("_src_port: %d ", _src_port);
	
	u_short _dst_port = ntohs(_tcp_hdr->dst_port);
	log_info("_dst_port: %d ", _dst_port);
	
	u_int _seq_num = ntohl(_tcp_hdr->seq_id);
	log_info("_seq_num: %lu ", _seq_num);
	
	u_int _ack_num = ntohl(_tcp_hdr->ack_id);
	log_info("_ack_num: %lu ", _ack_num);

	/*a bit for 4 bytes, only for save space*/	
	u_short _hdr_len = TH_OFF(_tcp_hdr) * 4;
	log_info("_hdr_len %d ", _hdr_len);
	
	dump_tcp_flags(_tcp_hdr->th_flags);
	
	u_short _window_size = ntohs(_tcp_hdr->th_win);
	log_info("win: %d ", _window_size);
	
	u_short _check_sum = ntohs(_tcp_hdr->th_sum);
	log_info("checksum: 0x%x ", _check_sum);	
	
	u_short _urg = ntohs(_tcp_hdr->th_urp);
	log_info("urg: %d ", _urg);
	
	log_info("\n");
}
