#include "SynFlood.h"
#include "PacketHeader.h"
#include<pcap.h>
#include<stdio.h>
#include<stdlib.h>
#include<string.h>
#include<arpa/inet.h>
#include<time.h>

int total=0;
extern void GetHexDumpGUI(const u_char *packet,bpf_u_int32 length,char *hexDump);

#define MAX_STATES 10000
#define ALPHABET_SIZE 256

int trie[MAX_STATES][ALPHABET_SIZE];
int fail[MAX_STATES];
char* threat_match[MAX_STATES];
int states_count = 1;

void init_aho_corasick()
{
    memset(trie, -1, sizeof(trie));
    memset(fail, -1, sizeof(fail));
    memset(threat_match, 0, sizeof(threat_match));
    states_count = 1;
}

void add_threat_signature(const char* keyword, const char* threat_type)
{
    int curr = 0;
    int i;
    for (i = 0; keyword[i] != '\0'; i++)
    {
        unsigned char c = (unsigned char)keyword[i];
        if (trie[curr][c] == -1)
        {
            trie[curr][c] = states_count++;
        }
        curr = trie[curr][c];
    }
    threat_match[curr] = strdup(threat_type);
}

void build_automaton()
{
    int queue[MAX_STATES];
    int front = 0, rear = 0;
    int c;
    for (c = 0; c < ALPHABET_SIZE; c++)
    {
        if (trie[0][c] != -1)
        {
            fail[trie[0][c]] = 0;
            queue[rear++] = trie[0][c];
        }
        else
        {
            trie[0][c] = 0;
        }
    }
    while (front < rear)
    {
        int curr = queue[front++];
        for (c = 0; c < ALPHABET_SIZE; c++)
        {
            if (trie[curr][c] != -1)
            {
                int f = fail[curr];
                while (trie[f][c] == -1) f = fail[f];
                fail[trie[curr][c]] = trie[f][c];
                queue[rear++] = trie[curr][c];
            }
        }
    }
}

void scan_payload_for_threats(const unsigned char* payload, int payload_len, const char* src_ip)
{
    int curr = 0;
    int i;
    for (i = 0; i < payload_len; i++)
    {
        unsigned char c = payload[i];
        while (trie[curr][c] == -1) curr = fail[curr];
        curr = trie[curr][c];
        
        if (threat_match[curr] != NULL)
        {
            // GUI তে থ্রেট সিগনেচার অ্যালার্ট পাঠানো
            printf("GUI_ALERT|SIGNATURE_MATCH|%s|%s\n", threat_match[curr], src_ip);
            fflush(stdout);
        }
    }
}

void setup_threat_engine()
{
    init_aho_corasick();
    add_threat_signature("USER root", "FTP_ROOT_LOGIN");
    add_threat_signature("PASS ", "FTP_PASSWORD_LEAK");
    add_threat_signature("eval(base64_decode", "PHP_MALWARE_INJECTION");
    add_threat_signature("cmd.exe", "REVERSE_SHELL_ATTEMPT");
    add_threat_signature("etc/passwd", "LOCAL_FILE_INCLUSION");
    
    build_automaton();
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

    char proto_name[25];
    strcpy(proto_name,"OTHER");
    
    char info[500];
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
            
        // ⚠️ NEW: AHO-CORASICK TCP PAYLOAD SCAN 
        if(payload_len>0)
        {
            unsigned char *payload_data;
            payload_data=(unsigned char *)(tcp_raw+tcp_header_len);
            scan_payload_for_threats(payload_data,payload_len,src_ip);
        }

        char syn_tag[10];
        syn_tag[0]='\0';
        
        int synFlagCheck;
        synFlagCheck=tcp_flags&0x02;
        
        if(synFlagCheck!=0)
            strcpy(syn_tag,"[SYN] ");

        if(src_port==80 || dst_port==80 || src_port==8080 || dst_port==8080)
        {
            strcpy(proto_name,"HTTP");
            sprintf(info,"%sPort: %d->%d Seq: %u Ack: %u Win: %u Len: %d",syn_tag,src_port,dst_port,seq,ack,win,payload_len);
        }
        else if(src_port==443 || dst_port==443)
        {
            strcpy(proto_name,"HTTPS");
            
            int isSniFound;
            isSniFound=0;
            
            char sni_name[256];
            sni_name[0]='\0';

            if(payload_len>=43)
            {
                unsigned char *tls_data;
                tls_data=(unsigned char *)(tcp_raw+tcp_header_len);
                
                if(tls_data[0]==0x16) 
                {
                    if(tls_data[5]==0x01) 
                    {
                        int offset;
                        offset=5;
                        offset=offset+1; 
                        offset=offset+3; 
                        offset=offset+2; 
                        offset=offset+32; 
                        
                        if(offset<payload_len)
                        {
                            int session_id_len;
                            session_id_len=tls_data[offset];
                            offset=offset+1+session_id_len;
                        }
                        
                        if(offset+2<=payload_len)
                        {
                            int cipher_suites_len;
                            cipher_suites_len=(tls_data[offset]<<8)|tls_data[offset+1];
                            offset=offset+2+cipher_suites_len;
                        }
                        
                        if(offset+1<=payload_len)
                        {
                            int comp_methods_len;
                            comp_methods_len=tls_data[offset];
                            offset=offset+1+comp_methods_len;
                        }
                        
                        if(offset+2<=payload_len)
                        {
                            int extensions_len;
                            extensions_len=(tls_data[offset]<<8)|tls_data[offset+1];
                            offset=offset+2;
                            
                            int ext_end;
                            ext_end=offset+extensions_len;
                            
                            if(ext_end>payload_len)
                            {
                                ext_end=payload_len;
                            }
                            
                            while(offset+4<=ext_end)
                            {
                                int ext_type;
                                ext_type=(tls_data[offset]<<8)|tls_data[offset+1];
                                
                                int ext_len;
                                ext_len=(tls_data[offset+2]<<8)|tls_data[offset+3];
                                
                                offset=offset+4;
                                
                                if(ext_type==0) 
                                {
                                    if(offset+2<=ext_end)
                                    {
                                        int local_offset;
                                        local_offset=offset+2;
                                        
                                        if(local_offset+3<=ext_end)
                                        {
                                            int name_type;
                                            name_type=tls_data[local_offset];
                                            
                                            int name_len;
                                            name_len=(tls_data[local_offset+1]<<8)|tls_data[local_offset+2];
                                            
                                            local_offset=local_offset+3;
                                            
                                            if(name_type==0 && local_offset+name_len<=ext_end)
                                            {
                                                if(name_len>255)
                                                {
                                                    name_len=255;
                                                }
                                                memcpy(sni_name,tls_data+local_offset,name_len);
                                                sni_name[name_len]='\0';
                                                isSniFound=1;
                                                break;
                                            }
                                        }
                                    }
                                }
                                offset=offset+ext_len;
                            }
                        }
                    }
                }
            }

            if(isSniFound!=0)
            {
                strcpy(proto_name,"HTTPS (DPI)");
                sprintf(info,"%s🌐 Domain Visited: %s",syn_tag,sni_name);
            }
            else
            {
                sprintf(info,"%sPort: %d->%d Seq: %u Ack: %u Win: %u Len: %d",syn_tag,src_port,dst_port,seq,ack,win,payload_len);
            }
        }
        else
        {
            strcpy(proto_name,"TCP");
            sprintf(info,"%sPort: %d->%d Seq: %u Ack: %u Win: %u Len: %d",syn_tag,src_port,dst_port,seq,ack,win,payload_len);
        }
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

        int total_ip_len;
        total_ip_len=ntohs(ip->length);
        
        int udp_payload_len;
        udp_payload_len=total_ip_len-ipHeaderLengthInBytes-8;

        if(src_port==53 || dst_port==53)
        {
            strcpy(proto_name,"DNS");
            char queried_domain[256];
            queried_domain[0]='\0';

            if(udp_payload_len > 12)
            {
                unsigned char *dns_data = (unsigned char *)(packet + totalOffset + 8);
                int qdcount = (dns_data[4] << 8) | dns_data[5]; 
                
                if(qdcount > 0)
                {
                    int offset = 12; 
                    int j = 0;
                    while(offset < udp_payload_len && dns_data[offset] != 0 && j < 250)
                    {
                        int len = dns_data[offset];
                        if((len & 0xC0) == 0xC0) break; 
                        offset++;
                        for(int k=0; k<len && offset < udp_payload_len; k++)
                        {
                            queried_domain[j++] = dns_data[offset++];
                        }
                        queried_domain[j++] = '.';
                    }
                    if(j > 0) queried_domain[j-1] = '\0'; // শেষের ডট (.) রিমুভ
                }
            }

            if(strlen(queried_domain) > 0) {
                sprintf(info,"🌐 DNS Query: %s", queried_domain);
            } else {
                sprintf(info,"Port: %d -> %d", src_port, dst_port);
            }
        }
        else if(src_port==443 || dst_port==443)
        {
            strcpy(proto_name,"QUIC/UDP");
            sprintf(info,"Encrypted QUIC Traffic Port: %d -> %d", src_port, dst_port);
        }
        else
        {
            strcpy(proto_name,"UDP");
            sprintf(info,"Port: %d -> %d", src_port, dst_port);
        }

        if(udp_payload_len>0)
        {
            unsigned char *udp_payload_data;
            udp_payload_data=(unsigned char *)(packet+totalOffset+8);
            scan_payload_for_threats(udp_payload_data,udp_payload_len,src_ip);
        }
    }

    char full_hex[10000]; 
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

    check_syn_anomaly(packet); 
 
}

void Realtimepacket(int protocol_choice)
{
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *handle;
    
    setup_threat_engine();
    
    handle=pcap_open_live("en0",65536,1,1000,errbuf);
    
    if(handle==NULL)
    {
        handle=pcap_open_live("any",65536,1,1000,errbuf);
        if(handle==NULL)
        {
            printf("Error opening device: %s\n",errbuf);
            return;
        }
    }
    
    pcap_loop(handle,0,packet_handler,(u_char*)&protocol_choice);
    pcap_close(handle);
}

void GetHexDumpGUI(const u_char *packet,bpf_u_int32 length,char *hexDump)
{
    hexDump[0]='\0';
    char tempBuf[50];
    
    bpf_u_int32 limit;
    limit=length;
    
    if(limit>2000)
    {
        limit=2000; 
    }
    
    bpf_u_int32 i;
    bpf_u_int32 j;
    
    for(i=0;i<limit;i=i+16)
    {
        sprintf(tempBuf,"%04X:  ",i);
        strcat(hexDump,tempBuf);
        
        for(j=0;j<16;j++)
        {
            if(i+j<limit)
            {
                sprintf(tempBuf,"%02X ",packet[i+j]);
                strcat(hexDump,tempBuf);
            }
            else
            {
                strcat(hexDump,"   "); 
            }
        }
        strcat(hexDump,"\\n"); 
    }
}
