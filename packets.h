#ifndef SNIFFER_PACKETS_H_
#define SNIFFER_PACKETS_H_

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <arpa/inet.h>
#include <stdint.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include "crc.h"

#define PROTOCOL_STR_SIZE 32

#define IPV4_HDR_RSIZE 20
#define IPV4_PROT_ICMP 1
#define IPV4_PROT_TCP 6
#define IPV4_PROT_UDP 17
#define IPV4_PROT_ENCAP 41
#define IPV4_PROT_SCTP 132

#define ARP_HDR_RSIZE 8
#define ARP_PROT_REQUEST 1
#define ARP_PROT_REPLY 2

#define ICMP_HDR_SIZE 8

#define UDP_HDR_SIZE 8

#define TCP_HDR_RSIZE 20

struct IPv4Header {
  struct iphdr header;
  uint32_t options[10];
  char opt_length;
};

struct TCPHeader {
  struct tcphdr header;
  unsigned char pseudo[IPV4_PSEUDOHDR_SIZE];
  uint32_t options[10];
  char opt_length;
};

struct UDPHeader {
  struct udphdr header;
  unsigned char pseudo[IPV4_PSEUDOHDR_SIZE];
};

struct ARPHeader {
  uint16_t htype;
  uint16_t ptype;
  uint8_t hlen;
  uint8_t plen;
  uint16_t oper;
  unsigned char *ptr;
};

struct ICMPHeader {
  uint8_t type;
  uint8_t code;
  uint16_t check;
  uint32_t data;
};

union HeaderUnion {
  struct ethhdr eth;
  struct IPv4Header ipv4;
  struct ARPHeader arp;
  struct ICMPHeader icmp;
  struct TCPHeader tcp;
  struct UDPHeader udp;
};

enum HeaderType {
  HDR_TYPE_ERROR,
  HDR_TYPE_ETH,
  HDR_TYPE_IPV4,
  HDR_TYPE_ARP,
  HDR_TYPE_ICMP,
  HDR_TYPE_TCP,
  HDR_TYPE_UDP
};

struct UniHeader {
  enum HeaderType type;
  const unsigned char *load_begin, *hdr_begin;
  int load_length;
  union HeaderUnion header;
};


extern void GetEtherHeader(const unsigned char *packet, struct ethhdr *header);
extern void PrintEtherHeader(const struct ethhdr *header);
extern int GetIPv4Header(const unsigned char *packet, int length, struct IPv4Header *ip_header);
extern void IPAdressToStr(uint32_t addr, char *str);
extern void PrintIPv4Header(const struct IPv4Header *ip_header);
extern int GetARPHeader(const unsigned char *packet, int length, struct ARPHeader *header);
extern void FreeARPHeader(const struct ARPHeader *header);
extern void PrintARPHeader(const struct ARPHeader *header);
extern void PrintHeader(const struct UniHeader *header);
extern int GetAllHeaders(const unsigned char *packet, int length, struct UniHeader *headers);
extern void ReallocateHeaders(const struct UniHeader *headers, int cnt);

#endif // SNIFFER_PACKETS_H_