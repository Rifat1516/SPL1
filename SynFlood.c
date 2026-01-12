#include <stdio.h>   
#include <stdlib.h>  
#include <string.h>      
#include <netinet/in.h>  
#include <netinet/ip.h>  
#include <sys/socket.h>
#include <arpa/inet.h>
#include <sys/types.h>
#include <unistd.h>
#include "PacketHeader.h"

#define MAX 100000

FILE *filepointer;
char fileName[100];
int pacekt_no;
long int fake_ip[MAX], tcp = 0, http = 0, ssl = 0;
long int false_no = -1, fake_num = -1;
struct Synfld spam[MAX];

int is_same(int address1[], u_int32_t address2[]);
void checking_syn(int address[], int s_a);
void check_flood();

int SynFlood (char *pcapfile) {
    struct globalhdr Global;
    struct packethdr packet_head;
    struct ethernethdr ether;
    struct IP Iphead;
    struct TCP Tcphead;
    unsigned char protocol;
    char flg[6];
    
    strcpy(fileName, pcapfile);
    filepointer = fopen(fileName, "rb");
    
    if (filepointer == NULL) return -1;

    fread(&Global, sizeof(struct globalhdr), 1, filepointer);
    tcp = 0; http = 0; ssl = 0; pacekt_no = 0;

    while(fread(&packet_head, sizeof(struct packethdr), 1, filepointer) == 1) {
        char source_ip[100], destination_ip[100];
        fread(&ether, sizeof(struct ethernethdr), 1, filepointer);
        
        if (ntohs(ether.ethType) == 2048) {
            fread(&Iphead, sizeof(struct IP), 1, filepointer);
            protocol = Iphead.protocol;
            int a1[4], a2[4];
            sprintf(source_ip, "%d.%d.%d.%d", Iphead.source[0], Iphead.source[1], Iphead.source[2], Iphead.source[3]);
            sprintf(destination_ip, "%d.%d.%d.%d", Iphead.destination[0], Iphead.destination[1], Iphead.destination[2], Iphead.destination[3]);
            for(int i=0; i<4; i++) { a1[i] = Iphead.source[i]; a2[i] = Iphead.destination[i]; }

            fseek(filepointer, (Iphead.IHL & 0x0f) * 4 - 20, SEEK_CUR);
            
            if (protocol == 6) {
                tcp++;
                fread(&Tcphead, sizeof(struct TCP), 1, filepointer);
                fseek(filepointer, ((Tcphead.tcp_resoff & 0xf0) >> 4) * 4 - 20, SEEK_CUR);

                for (int i = 0; i < 6; i++) flg[i] = (Tcphead.tcp_flag & (1 << (5 - i))) ? 1 : 0;

                if (flg[4] == 1 && flg[1] == 0) checking_syn(a2, 1);
                else if (flg[4] == 1 && flg[1] == 1) checking_syn(a1, 2);
            }
        } else {
            fseek(filepointer, packet_head.ocLen - 14, SEEK_CUR);
        }
        pacekt_no++;
    }
    check_flood();
    if (fake_num >= 0) {
        for (int i = 0; i <= fake_num; i++) {
            int idx = fake_ip[i];
            printf("IP: %d.%d.%d.%d | SYN: %llu | SYN_ACK: %llu\n", 
                   spam[idx].IP[0], spam[idx].IP[1], spam[idx].IP[2], spam[idx].IP[3],
                   (unsigned long long)spam[idx].syn, (unsigned long long)spam[idx].syn_ack);
        }
    }
    fclose(filepointer);
    return 0;
}

int is_same(int address1[], u_int32_t address2[]) {
    for (int i = 0; i < 4; i++) if (address1[i] != (int)address2[i]) return 0;
    return 1;
}

void checking_syn(int address[], int s_a) {
    long int ind = -1;
    for (long int i = 0; i <= false_no; i++) if (is_same(address, spam[i].IP)) { ind = i; break; }
    if (ind != -1) {
        if (s_a == 1) spam[ind].syn++; else spam[ind].syn_ack++;
    } else {
        false_no++;
        for (int i = 0; i < 4; i++) spam[false_no].IP[i] = address[i];
        if (s_a == 1) { spam[false_no].syn = 1; spam[false_no].syn_ack = 0; }
        else { spam[false_no].syn_ack = 1; spam[false_no].syn = 0; }
    }
}

void check_flood() {
    for (long int i = 0; i <= false_no; i++) if ((spam[i].syn - spam[i].syn_ack) > 15) fake_ip[++fake_num] = i;
}