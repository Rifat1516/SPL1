#include <stdio.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netinet/ip_icmp.h>
#include "PacketHeader.h"

extern int total;
extern struct sockaddr_in source_addr, dest_addr;
extern FILE *fp;

void PrintSeparator() {
    printf("______________________________________________________________________\n");
}

void LogPacketToFile(const char* proto, char* src, char* dst, int sport, int dport) {
    if (fp != NULL) {
        fprintf(fp, "Packet No: %d | Protocol: %s\n", total, proto);
        fprintf(fp, "Source: %s:%d\n", src, sport);
        fprintf(fp, "Destination: %s:%d\n", dst, dport);
        fprintf(fp, "--------------------------------------------------\n");
        fflush(fp);
    }
}

void DecodeIPHeader(const u_char* buff) {
    struct ip *ip = (struct ip *)buff;
    source_addr.sin_addr.s_addr = ip->ip_src.s_addr;
    dest_addr.sin_addr.s_addr = ip->ip_dst.s_addr;

    printf("\n[Layer 3: IP Header]\n");
    printf(" |-Source IP        : %s\n", inet_ntoa(source_addr.sin_addr));
    printf(" |-Destination IP   : %s\n", inet_ntoa(dest_addr.sin_addr));
    printf(" |-TTL              : %d\n", (unsigned int)ip->ip_ttl);
    printf(" |-Protocol         : %d\n", (unsigned int)ip->ip_p);
}

void tcpPacket(const u_char* buff, int dataSize) {
    struct ip *ip = (struct ip *)buff;
    unsigned short iphdrlen = ip->ip_hl * 4;
    struct tcphdr *tcp = (struct tcphdr*)(buff + iphdrlen);
    DecodeIPHeader(buff);
    printf("[Layer 4: TCP Header]\n");
    printf(" |-Source Port      : %u\n", ntohs(tcp->th_sport));
    printf(" |-Destination Port : %u\n", ntohs(tcp->th_dport));
    LogPacketToFile("TCP", inet_ntoa(source_addr.sin_addr), inet_ntoa(dest_addr.sin_addr), ntohs(tcp->th_sport), ntohs(tcp->th_dport));
    PrintSeparator();
}

void udpPacket(const u_char* buff, int dataSize) {
    struct ip *ip = (struct ip *)buff;
    unsigned short iphdrlen = ip->ip_hl * 4;
    struct udphdr *udp = (struct udphdr*)(buff + iphdrlen);
    DecodeIPHeader(buff);
    printf("[Layer 4: UDP Header]\n");
    printf(" |-Source Port      : %u\n", ntohs(udp->uh_sport));
    printf(" |-Destination Port : %u\n", ntohs(udp->uh_dport));
    LogPacketToFile("UDP", inet_ntoa(source_addr.sin_addr), inet_ntoa(dest_addr.sin_addr), ntohs(udp->uh_sport), ntohs(udp->uh_dport));
    PrintSeparator();
}

void icmpPacket(const u_char* buff, int dataSize) {
    struct ip *ip = (struct ip *)buff;
    unsigned short iphdrlen = ip->ip_hl * 4;
    struct icmp *icmp = (struct icmp *)(buff + iphdrlen);
    DecodeIPHeader(buff);
    printf("[Layer 4: ICMP Header]\n");
    printf(" |-ICMP Type : %d\n", (unsigned int)(icmp->icmp_type));
    printf(" |-ICMP Code : %d\n", (unsigned int)(icmp->icmp_code));
    // FIXED: Use icmp_cksum for macOS
    printf(" |-Checksum  : %d\n", ntohs(icmp->icmp_cksum));
    LogPacketToFile("ICMP", inet_ntoa(source_addr.sin_addr), inet_ntoa(dest_addr.sin_addr), 0, 0);
    PrintSeparator();
}