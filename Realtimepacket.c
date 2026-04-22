#include<stdio.h>
#include<stdlib.h>
#include<string.h>
#include<pcap.h>
#include<arpa/inet.h>
#include<sys/types.h>
#include<unistd.h>
#include<time.h>
#include<ctype.h>
#include"PacketHeader.h"
#include"Realtimepacket.h"

int total=0;

void GetHexDumpGUI(const void *data,size_t size,char *output)
{
    unsigned char *p;
    p=(unsigned char *)data;
    
    char hex_part[60];
    char ascii_part[25];
    output[0]='\0';
    
    size_t i;
    size_t j;
    
    for(i=0;i<size;i=i+16)
    {
        hex_part[0]='\0';
        ascii_part[0]='\0';

        for(j=0;j<16;j++)
        {
            size_t currentIndex;
            currentIndex=i+j;
            
            if(currentIndex<size)
            {
                unsigned char currentValue;
                currentValue=p[currentIndex];
                
                char tempForHex[5];
                sprintf(tempForHex,"%02X ",currentValue);
                strcat(hex_part,tempForHex);
                
                int printableCheck;
                printableCheck=isprint(currentValue);
                
                char tempForAscii[5];
                if(printableCheck!=0)
                {
                    sprintf(tempForAscii,"%c",currentValue);
                }
                else
                {
                    sprintf(tempForAscii,".");
                }
                strcat(ascii_part,tempForAscii);
            }
            else
            {
                char emptySpace[5];
                sprintf(emptySpace,"   ");
                strcat(hex_part,emptySpace);
            }
        }
        
        char fullLine[120];
        sprintf(fullLine,"%s | %s\\n",hex_part,ascii_part);
        strcat(output,fullLine);
        
        size_t currentOutputLength;
        currentOutputLength=strlen(output);
        
        if(currentOutputLength>1500)
            break;
    }
}

void packet_handler(u_char *args,const struct pcap_pkthdr *header,const u_char *packet)
{
    bpf_u_int32 captureLength;
    captureLength=header->caplen;
    
    if(captureLength<14)
        return;

    unsigned char byte12;
    byte12=packet[12];
    unsigned char byte13;
    byte13=packet[13];
    
    uint16_t eth_type;
    eth_type=(byte12<<8)|byte13;
    
    if(eth_type!=0x0800)
        return;

    struct IP *ip;
    ip=(struct IP *)(packet+14);

    int protocol_choice;
    protocol_choice=0;
    
    if(args!=NULL)
    {
        int *ptrArg;
        ptrArg=(int *)args;
        protocol_choice=*ptrArg;
    }

    unsigned char currentProtocol;
    currentProtocol=ip->protocol;

    if(protocol_choice==1 && currentProtocol!=6)
        return;
    if(protocol_choice==2 && currentProtocol!=1)
        return;
    if(protocol_choice==3 && currentProtocol!=17)
        return;

    total++;

    struct ethernethdr *eth;
    eth=(struct ethernethdr *)packet;
    
    char src_mac[20];
    char dst_mac[20];
    
    sprintf(src_mac,"%02X:%02X:%02X:%02X:%02X:%02X",eth->source[0],eth->source[1],eth->source[2],eth->source[3],eth->source[4],eth->source[5]);
    sprintf(dst_mac,"%02X:%02X:%02X:%02X:%02X:%02X",eth->destination[0],eth->destination[1],eth->destination[2],eth->destination[3],eth->destination[4],eth->destination[5]);

    struct tm *ltime;
    char timestr[20];
    time_t local_tv_sec;
    local_tv_sec=header->ts.tv_sec;
    
    ltime=localtime(&local_tv_sec);
    strftime(timestr,sizeof(timestr),"%H:%M:%S",ltime);

    char src_ip[20];
    char dst_ip[20];
    
    sprintf(src_ip,"%d.%d.%d.%d",ip->source[0],ip->source[1],ip->source[2],ip->source[3]);
    sprintf(dst_ip,"%d.%d.%d.%d",ip->destination[0],ip->destination[1],ip->destination[2],ip->destination[3]);

    char proto_name[15];
    strcpy(proto_name,"OTHER");
    
    char info[250];
    strcpy(info,"Data Packet");

    if(currentProtocol==6)
    {
        int ipHeaderLengthInWords;
        ipHeaderLengthInWords=ip->IHL&0x0F;
        
        int ipHeaderLengthInBytes;
        ipHeaderLengthInBytes=ipHeaderLengthInWords*4;
        
        int totalOffset;
        totalOffset=14+ipHeaderLengthInBytes;
        
        unsigned char *tcp_raw;
        tcp_raw=(unsigned char *)(packet+totalOffset);
        
        unsigned char srcPortHigh;
        srcPortHigh=tcp_raw[0];
        unsigned char srcPortLow;
        srcPortLow=tcp_raw[1];
        int src_port;
        src_port=(srcPortHigh<<8)|srcPortLow;
        
        unsigned char dstPortHigh;
        dstPortHigh=tcp_raw[2];
        unsigned char dstPortLow;
        dstPortLow=tcp_raw[3];
        int dst_port;
        dst_port=(dstPortHigh<<8)|dstPortLow;

        uint32_t seq1,seq2,seq3,seq4;
        seq1=tcp_raw[4];
        seq2=tcp_raw[5];
        seq3=tcp_raw[6];
        seq4=tcp_raw[7];
        uint32_t seq;
        seq=(seq1<<24)|(seq2<<16)|(seq3<<8)|seq4;

        uint32_t ack1,ack2,ack3,ack4;
        ack1=tcp_raw[8];
        ack2=tcp_raw[9];
        ack3=tcp_raw[10];
        ack4=tcp_raw[11];
        uint32_t ack;
        ack=(ack1<<24)|(ack2<<16)|(ack3<<8)|ack4;

        unsigned char dataOffsetByte;
        dataOffsetByte=tcp_raw[12];
        int tcpHeaderLengthInWords;
        tcpHeaderLengthInWords=dataOffsetByte>>4;
        int tcp_header_len;
        tcp_header_len=tcpHeaderLengthInWords*4;

        unsigned char tcp_flags;
        tcp_flags=tcp_raw[13];

        unsigned char winHigh;
        winHigh=tcp_raw[14];
        unsigned char winLow;
        winLow=tcp_raw[15];
        uint16_t win;
        win=(winHigh<<8)|winLow;

        int total_ip_len;
        total_ip_len=ntohs(ip->length);
        
        int payload_len;
        payload_len=total_ip_len-ipHeaderLengthInBytes-tcp_header_len;
        
        if(payload_len<0)
            payload_len=0;

        if(src_port==80 || dst_port==80 || src_port==8080 || dst_port==8080)
            strcpy(proto_name,"HTTP");
        else if(src_port==443 || dst_port==443)
            strcpy(proto_name,"HTTPS");
        else
            strcpy(proto_name,"TCP");

        char syn_tag[10];
        syn_tag[0]='\0';
        
        int synFlagCheck;
        synFlagCheck=tcp_flags&0x02;
        
        if(synFlagCheck!=0)
            strcpy(syn_tag,"[SYN] ");

        sprintf(info,"%sPort: %d->%d Seq: %u Ack: %u Win: %u Len: %d",syn_tag,src_port,dst_port,seq,ack,win,payload_len);
    }
    else if(currentProtocol==1)
    {
        strcpy(proto_name,"ICMP");
        strcpy(info,"Echo (ping) Request/Reply");
    }
    else if(currentProtocol==17)
    {
        int ipHeaderLengthInWords;
        ipHeaderLengthInWords=ip->IHL&0x0F;
        
        int ipHeaderLengthInBytes;
        ipHeaderLengthInBytes=ipHeaderLengthInWords*4;
        
        int totalOffset;
        totalOffset=14+ipHeaderLengthInBytes;

        struct udphdr *udp;
        udp=(struct udphdr *)(packet+totalOffset);
        
        int src_port;
        src_port=ntohs(udp->source);
        
        int dst_port;
        dst_port=ntohs(udp->dest);

        if(src_port==53 || dst_port==53)
            strcpy(proto_name,"DNS");
        else
            strcpy(proto_name,"UDP");

        sprintf(info,"Port: %d -> %d",src_port,dst_port);
    }

    char full_hex[2000];
    bpf_u_int32 capturedLength;
    capturedLength=header->caplen;
    
    GetHexDumpGUI(packet,capturedLength,full_hex);

    int msTime;
    msTime=header->ts.tv_usec/1000;
    int packetLength;
    packetLength=header->len;
    int packetTtl;
    packetTtl=ip->ttl;

    printf("GUI_DATA|%d|%s.%03d|%s|%s|%s|%d|%s|%s|%s|%d|%s\n",total,timestr,msTime,src_ip,dst_ip,proto_name,packetLength,info,src_mac,dst_mac,packetTtl,full_hex);
    fflush(stdout);
}

int Realtimepacket(char *target,int x)
{
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *handle;
    total=0;
    
    int isLive;
    isLive=strcmp(target,"live");

    if(isLive==0)
    {
        handle=pcap_open_live("en0",BUFSIZ,1,100,errbuf);
    }
    else
    {
        handle=pcap_open_offline(target,errbuf);
    }

    if(handle==NULL)
    {
        printf("Error opening capture: %s\n",errbuf);
        return -1;
    }

    u_char *pointerToArg;
    pointerToArg=(u_char *)&x;
    
    pcap_loop(handle,0,packet_handler,pointerToArg);
    pcap_close(handle);
    
    return 0;
}
