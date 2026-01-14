#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <netinet/in.h>
#include "PacketHeader.h"

int ICMP_num = 0;
int UDP_num  = 0;
int TCP_num  = 0;
int others   = 0;
int total    = 0;

struct sockaddr_in source_addr, dest_addr;
FILE *fp;

int Realtimepacket(int x);

void PrintVersionInfo() {
    printf("\n##########################################################\n");
    printf("#                                                        #\n");
    printf("#                  PACKANALYZER SYSTEM                    #\n");
    printf("#          Network Protocol Security & Monitoring         #\n");
    printf("#                                                        #\n");
    printf("##########################################################\n");
}

void PrintUsageManual(char *progName) {
    printf("\n[!] ERROR: Missing or Invalid Arguments\n\n");
    printf("CONFIGURATION GUIDE:\n");
    printf("----------------------------------------------------------\n");
    printf("Command Execution: sudo %s -i [Mode]\n\n", progName);
    printf("AVAILABLE MODES:\n");
    printf("  Mode [1] : TCP Protocol (Transmission Control)\n");
    printf("  Mode [2] : ICMP Protocol (Network Control Messages)\n");
    printf("  Mode [3] : UDP Protocol (User Datagrams)\n\n");
    printf("SYSTEM REQUIREMENTS:\n");
    printf("  - Root access (sudo) is required for raw socket access.\n");
    printf("  - Libpcap must be installed on the host system.\n");
    printf("----------------------------------------------------------\n\n");
}

void FinalizeStatistics() {
    printf("\n\nFinal Session Summary Data:\n");
    printf("==========================================================\n");
    printf("  Total Processed Packets  : %-10d\n", total);
    printf("  Total TCP Packets        : %-10d\n", TCP_num);
    printf("  Total UDP Packets        : %-10d\n", UDP_num);
    printf("  Total ICMP Packets       : %-10d\n", ICMP_num);
    printf("  Unknown/Other Protocols  : %-10d\n", others);
    printf("==========================================================\n");
    printf("Results have been archived in PacketInfo.txt\n\n");
}

int ValidateSystemEnvironment() {
    uid_t uid = getuid();
    if (uid != 0) {
        return 0;
    }
    return 1;
}

const char* GetProtocolName(int mode) {
    if (mode == 1) return "TCP (Layer 4)";
    if (mode == 2) return "ICMP (Layer 3/4 Control)";
    if (mode == 3) return "UDP (Layer 4)";
    return "Unknown";
}

int main(int argc, char *argv[]) {
    int executionResult;
    int protocolSelection;

    PrintVersionInfo();

    if (!ValidateSystemEnvironment()) {
        printf("\n[CRITICAL ERROR]: Root privileges not detected.\n");
        printf("Please re-run the application using 'sudo'.\n\n");
        return -1;
    }

    if (argc < 3) {
        PrintUsageManual(argv[0]);
        return 1;
    }

    if (strcmp(argv[1], "-i") != 0) {
        printf("\n[ERROR]: Unrecognized flag '%s'. Use '-i' for interface mode.\n", argv[1]);
        PrintUsageManual(argv[0]);
        return 1;
    }

    protocolSelection = atoi(argv[2]);

    if (protocolSelection < 1 || protocolSelection > 3) {
        printf("\n[ERROR]: Invalid mode selection: %d\n", protocolSelection);
        PrintUsageManual(argv[0]);
        return 1;
    }

    printf("\n[SYSTEM]: Configuration validated successfully.\n");
    printf("[SYSTEM]: Protocol Filter set to: %s\n", GetProtocolName(protocolSelection));
    printf("[SYSTEM]: Attempting to bind to hardware interface...\n");

    executionResult = Realtimepacket(protocolSelection);

    if (executionResult != 0) {
        printf("\n[SYSTEM]: Engine returned error code: %d\n", executionResult);
        printf("[SYSTEM]: Check device availability and try again.\n");
        return executionResult;
    }

    FinalizeStatistics();

    printf("[SYSTEM]: Process complete. Shutting down.\n\n");

    return 0;
}