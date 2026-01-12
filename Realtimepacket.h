#include <sys/types.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netinet/ip_icmp.h>

/* These prototypes remain the same, but now they rely on Mac-compatible headers */
void IPheader(unsigned char*, int);
void tcpPacket(unsigned char*, int);
void udpPacket(unsigned char*, int);
void icmpPacket(unsigned char*, int);
void Hexdata(unsigned char*, int);
int sslPacket(unsigned char*, int);
void CapturingPacket(unsigned char*, int);
int Realtimepacket(int x); // Added 'int x' to match your recent implementation