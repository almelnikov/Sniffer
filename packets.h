#ifndef SNIFFER_PACKETS_H_
#define SNIFFER_PACKETS_H_

#include <stdio.h>
#include <string.h>
#include <arpa/inet.h>
#include <linux/if_ether.h>

extern void GetEtherHeader(const unsigned char *packet, struct ethhdr *header);
extern void PrintEtherHeader(struct ethhdr *header);

#endif // SNIFFER_PACKETS_H_