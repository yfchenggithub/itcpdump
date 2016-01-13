#ifndef ICMP_HDR_H
#define ICMP_HDR_H
#include <sys/types.h>
/*
Structure of an icmp header.
*/

#define uint8_t unsigned char
#define uint16_t unsigned short 

typedef struct _sniff_icmp_hdr
{
	uint8_t icmp_type; /*type of message*/
	uint8_t icmp_code; /*type sub code*/
	uint16_t icmp_cksum; /*checksum*/
}sniff_icmp_hdr_t;

void dump_icmp_hdr(const sniff_icmp_hdr_t* _icmp_hdr);
void dump_icmp_type(uint8_t _type);
void dump_icmp_code(uint8_t _code);
#endif
