#ifndef PACKET_HEADERS_INCLUDED
#define PACKET_HEADERS_INCLUDED

#include<sys/types.h>
#include<stdint.h>
#include<net/ethernet.h>

struct globalhdr
{
    uint32_t magicNumber;
    uint16_t versionMajor;
    uint16_t versionMinor;
    uint32_t time;
    uint32_t sigfigs;
    uint32_t snaplen;
    uint32_t network;
};
struct packethdr
{
    uint32_t tSec;
    uint32_t tuSec;
    uint32_t ocLen;
    uint32_t packLen;
};
struct ethernethdr
{
    u_char destination[6];
    u_char source[6];
    uint16_t ethType;
};
struct tcphdr
{
    uint16_t source;
    uint16_t dest;
    uint32_t seq;
    uint32_t ack_seq;
    uint16_t skip:4;
    uint16_t doff:4;
    uint16_t fin:1;
    uint16_t syn:1;
    uint16_t rst:1;
    uint16_t psh:1;
    uint16_t ack:1;
    uint16_t urg:1;
    uint16_t skip2:2;
    uint16_t window;
    uint16_t check;
    uint16_t urg_ptr;
};

// Structure for UDP Header (8 Bytes)
struct udphdr
{
    uint16_t source;
    uint16_t dest;
    uint16_t len;
    uint16_t check;
};
struct sslhdr
{
    u_char type;
    u_char ver1;
    u_char ver2;
    uint16_t length;
};
struct Synfld
{
    uint32_t IP[4];
    uint64_t syn;
    uint64_t syn_ack;
};
struct IP
{
    u_char IHL;
    u_char tos;
    uint16_t length;
    uint16_t id;
    uint16_t fragment;
    u_char ttl;
    u_char protocol;
    uint16_t checksum;
    u_char source[4];
    u_char destination[4];
};
struct TCP
{
    uint16_t srcport;
    uint16_t destport;
    uint32_t seq;
    uint32_t ack;
    u_char doff;
    u_char flags;
    uint16_t window;
    uint16_t checksum;
    uint16_t urgptr;
};

#endif