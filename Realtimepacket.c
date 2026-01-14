#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <pcap.h>
#include <netinet/ip.h>
#include <arpa/inet.h>
#include <unistd.h>
#include "PacketHeader.h"

extern int ICMP_num, UDP_num, TCP_num, others, total;
extern FILE *fp;

void tcpPacket(const u_char* buff, int dataSize);
void udpPacket(const u_char* buff, int dataSize);
void icmpPacket(const u_char* buff, int dataSize);


int verify_log_system() {
    fp = fopen("PacketInfo.txt", "a");
    if (fp == NULL) {
        return 0;
    }
    return 1;
}

const char* get_protocol_string(unsigned char proto_id) {
    switch (proto_id) {
        case IPPROTO_TCP:  return "TCP (Transmission Control)";
        case IPPROTO_UDP:  return "UDP (User Datagram)";
        case IPPROTO_ICMP: return "ICMP (Internet Control)";
        default:           return "Other/Unknown";
    }
}


void log_timestamp() {
    time_t now;
    time(&now);
    fprintf(fp, "\n[Timestamp: %s]", ctime(&now));
}

void print_ui_line() {
    printf("----------------------------------------------------------------------\n");
}

void clear_terminal() {
    printf("\033[H\033[J");
}


void show_startup_banner(const char* device) {
    clear_terminal();
    printf("######################################################################\n");
    printf("#                                                                    #\n");
    printf("#                    PACKET ANALYZER ENGINE                          #\n");
    printf("#              Midterm Project: Protocol Decoding                    #\n");
    printf("#                                                                    #\n");
    printf("######################################################################\n");
    printf("  Listening on: %s\n", device);
    printf("  Packet Size : 65536 bytes (Max)\n");
    printf("  Promiscuous : Enabled\n");
    printf("  Logging     : Active (PacketInfo.txt)\n");
    printf("######################################################################\n\n");
}

void show_table_header() {
    printf("%-8s %-18s %-18s %-10s %-8s\n", 
           "ID", "Source Address", "Dest Address", "Protocol", "Length");
    print_ui_line();
}

void show_shutdown_summary() {
    print_ui_line();
    printf("                NETWORK CAPTURE FINAL REPORT                  \n");
    print_ui_line();
    printf("  [+] Total Packets Processed : %-5d\n", total);
    printf("  [+] TCP Stream Count        : %-5d\n", TCP_num);
    printf("  [+] UDP Datagram Count      : %-5d\n", UDP_num);
    printf("  [+] ICMP Message Count      : %-5d\n", ICMP_num);
    printf("  [+] Miscellaneous Traffic   : %-5d\n", others);
    print_ui_line();
    printf("Status: Log file successfully synchronized.\n\n");
}


struct ip* decapsulate_to_layer3(const u_char* raw_packet) {
    return (struct ip *)(raw_packet + 14);
}


void route_packet_by_protocol(struct ip* ip_hdr, int filter, const u_char* packet, int size) {
    unsigned char protocol_type = ip_hdr->ip_p;

    if (protocol_type == IPPROTO_TCP) {
        TCP_num++;
        if (filter == 1) {
            tcpPacket((const u_char*)ip_hdr, size);
        }
    } 
    else if (protocol_type == IPPROTO_UDP) {
        UDP_num++;
        if (filter == 3) {
            udpPacket((const u_char*)ip_hdr, size);
        }
    } 
    else if (protocol_type == IPPROTO_ICMP) {
        ICMP_num++;
        if (filter == 2) {
            icmpPacket((const u_char*)ip_hdr, size);
        }
    } 
    else {
        others++;
    }
}

void CapturingPacket(u_char *args, const struct pcap_pkthdr *header, const u_char *packet) {
    int filter_choice = *(int *)args;
    int data_len = header->len;

    // Layer 3 Decapsulation
    struct ip *ip = decapsulate_to_layer3(packet);
    total++;

    // Logging Meta-data
    log_timestamp();
    fprintf(fp, "Packet ID: %d | Size: %d bytes | Proto: %s\n", 
            total, data_len, get_protocol_string(ip->ip_p));

    // Displaying brief info in Terminal table
    printf("%-8d %-18s %-18s %-10s %-8d\n", 
           total, inet_ntoa(ip->ip_src), inet_ntoa(ip->ip_dst), 
           (ip->ip_p == 6) ? "TCP" : (ip->ip_p == 17) ? "UDP" : "ICMP", data_len);

    // Deep Analysis
    route_packet_by_protocol(ip, filter_choice, packet, data_len);
}


pcap_t* open_network_interface(const char* device_name, char* err_buffer) {
    pcap_t* handle;
    
    handle = pcap_open_live(device_name, 65536, 1, 1000, err_buffer);
    
    if (handle == NULL) {
        fprintf(stderr, "[ERROR] Interface Initialization Failed.\n");
        return NULL;
    }
    
    return handle;
}

int Realtimepacket(int x) {
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *handle;
    char *target_dev = "en0"; // macOS WiFi Interface

    // Phase 1: Verify Hardware and Software access
    if (!verify_log_system()) {
        printf("[FATAL] Log system failed to initialize.\n");
        return -1;
    }

    // Phase 2: Open Interface
    handle = open_network_interface(target_dev, errbuf);
    if (handle == NULL) {
        printf("[FATAL] %s\n", errbuf);
        fclose(fp);
        return 2;
    }

    // Phase 3: Setup UI
    show_startup_banner(target_dev);
    show_table_header();

    // Phase 4: Main Execution Loop
    /* * Second parameter '0' means loop forever until interrupted. 
     */
    pcap_loop(handle, 0, CapturingPacket, (u_char *)&x);

    // Phase 5: Cleanup and Finalize
    pcap_close(handle);
    show_shutdown_summary();
    fclose(fp);

    return 0;
}
