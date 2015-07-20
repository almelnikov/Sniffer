#ifndef SNIFFER_PACKETS_H_
#define SNIFFER_PACKETS_H_

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <arpa/inet.h>
#include <stdint.h>
#include <linux/if_ether.h>
#include <linux/ip.h>

#define PROTOCOL_STR_SIZE 32

#define IPV4_PROT_ICMP 1
#define IPV4_PROT_TCP 6
#define IPV4_PROT_UDP 17
#define IPV4_PROT_ENCAP 41
#define IPV4_PROT_SCTP 132

#define ARP_HDR_RSIZE 8
#define ARP_PROT_REQUEST 1
#define ARP_PROT_REPLY 2

struct IPv4Header {
  struct iphdr header;
  uint32_t options[10];
  char opt_length;
};

struct ARPHeader {
  uint16_t htype;
  uint16_t ptype;
  uint8_t hlen;
  uint8_t plen;
  uint16_t oper;
  unsigned char *ptr;
};

/*
union HeaderUnion {
  struct ethhdr eth;
  struct IPv4Header ipv4;
};

enum HeaderType {
  HDR_TYPE_ETH,
  HDR_TYPE_IPV4,
};

struct UniHeader {
  enum HeaderType type;
  int load_begin, load_end;
  union HeaderUnion header;
};
*/

extern void GetEtherHeader(const unsigned char *packet, struct ethhdr *header);
extern void PrintEtherHeader(const struct ethhdr *header);
extern void GetIPv4Header(const unsigned char *packet, struct IPv4Header *ip_header);
extern void IPAdressToStr(uint32_t addr, char *str);
extern void PrintIPv4Header(const struct IPv4Header *ip_header);
extern int GetARPHeader(const unsigned char *packet, int length, struct ARPHeader *header);
extern void FreeARPHeader(struct ARPHeader *header);
extern void PrintARPHeader(const struct ARPHeader *header);

#endif // SNIFFER_PACKETS_H_