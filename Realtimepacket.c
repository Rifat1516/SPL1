#include<stdio.h>   
#include<stdlib.h>  
#include<string.h>      
#include<netinet/ip.h>  
#include<netinet/tcp.h>
#include<netinet/udp.h>
#include<netinet/ip_icmp.h>
#include<sys/socket.h>
#include<arpa/inet.h>
#include<sys/types.h>
#include<unistd.h>
#include"PacketHeader.h"

#ifdef __APPLE__
#define saddr ip_src.s_addr
#define daddr ip_dst.s_addr
#define protocol ip_p
#define tot_len ip_len
#define ihl ip_hl
#define version ip_v
#define type icmp_type
#define code icmp_code
#endif

void IPheader(unsigned char*,int);
void tcpPacket(unsigned char*,int);
void udpPacket(unsigned char*,int);
void icmpPacket(unsigned char*,int);
void Hexdata(unsigned char*,int);
int sslPacket(unsigned char*,int);
void CapturingPacket(unsigned char*,int);

extern int ICMP_num, UDP_num, TCP_num, others, total;
extern struct sockaddr_in source_addr, dest_addr;
extern FILE *fp;

int Realtimepacket(int x){
    struct sockaddr saddr_raw;
    socklen_t sockaddSize;
    int dataSize;
    unsigned char *buff = (unsigned char *)malloc(65536);
    int rawSocket;

    fp=fopen("PacketInfo.txt","w+");
    
    switch(x) {
        case 1: rawSocket = socket(AF_INET, SOCK_RAW, IPPROTO_TCP); break;
        case 2: rawSocket = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP); break;
        case 3: rawSocket = socket(AF_INET, SOCK_RAW, IPPROTO_UDP); break;
        default: return -6;
    }

    if(rawSocket < 0) {
        printf("Socket Error. Run with sudo.\n");
        return -2;
    }

    printf("!!!!!!!!! Starting Capture !!!!!!!!!!!\n");

    while(1){
        sockaddSize = sizeof(struct sockaddr);
        dataSize = recvfrom(rawSocket, buff, 65536, 0, &saddr_raw, &sockaddSize);
        if(dataSize < 0) break;
        CapturingPacket(buff, dataSize);
        usleep(10000); 
    }
    close(rawSocket);
    return 0;
}

void CapturingPacket(unsigned char* buff, int dataSize){
    struct ip *ip = (struct ip*)buff;
    total++;
    switch (ip->protocol) {
        case 1:  ICMP_num++; icmpPacket(buff, dataSize); break;
        case 6:  TCP_num++; tcpPacket(buff, dataSize); break;
        case 17: UDP_num++; udpPacket(buff, dataSize); break;
        default: others++; break;
    }
}

void IPheader(unsigned char* buff, int dataSize) {
    struct ip *ip = (struct ip *)buff;
    source_addr.sin_addr.s_addr = ip->saddr;
    dest_addr.sin_addr.s_addr = ip->daddr;

    fprintf(fp, "\nIP Header\n");
    fprintf(fp, "     Source IP         : %s\n", inet_ntoa(source_addr.sin_addr));
    fprintf(fp, "     Destination IP    : %s\n", inet_ntoa(dest_addr.sin_addr));
    fprintf(fp, "     IP Version        : %d\n", ip->version);
    fprintf(fp, "     Protocol          : %d\n", ip->protocol);
    fprintf(fp, "     IP Total Length   : %d Bytes\n", ntohs(ip->tot_len));
    fprintf(fp, "     IP Header Length  : %d Bytes\n", ip->ihl * 4);
}

void tcpPacket(unsigned char* buff, int dataSize) {
    struct ip *ip = (struct ip *)buff;
    unsigned short iphdrlen = ip->ihl * 4;
    struct tcphdr *tcp = (struct tcphdr*)(buff + iphdrlen);

    IPheader(buff, dataSize);
    printf("%-20d%-20s%-20s%-20s%-20d%-20d\n", total, inet_ntoa(source_addr.sin_addr), 
           inet_ntoa(dest_addr.sin_addr), "TCP", ntohs(tcp->th_sport), ntohs(tcp->th_dport));
}

void udpPacket(unsigned char *buff, int dataSize) {
    struct ip *ip = (struct ip *)buff;
    unsigned short iphdrlen = ip->ihl * 4;
    struct udphdr *udp = (struct udphdr*)(buff + iphdrlen);

    IPheader(buff, dataSize);
    printf("%-20d%-20s%-20s%-20s%-20d%-20d\n", total, inet_ntoa(source_addr.sin_addr), 
           inet_ntoa(dest_addr.sin_addr), "UDP", ntohs(udp->uh_sport), ntohs(udp->uh_dport));
}

void icmpPacket(unsigned char* buff, int dataSize) {
    struct ip *ip = (struct ip *)buff;
    unsigned short iphdrlen = ip->ihl * 4;
    struct icmp *icmp = (struct icmp *)(buff + iphdrlen);

    IPheader(buff, dataSize);
    printf("%-20d%-15s%-20d%-20d\n", total, "ICMP", icmp->type, icmp->code);
}
