#ifndef SYNFLOOD_H
#define SYNFLOOD_H

#include<pcap.h>

void check_syn_anomaly(const u_char *packet);
void SynFlood(char *targetIP);

#endif
