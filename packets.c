#include "packets.h"

void GetEtherHeader(const unsigned char *packet, struct ethhdr *header) {
  memcpy(header, packet, sizeof(*header));  // Packed struct
  header->h_proto = ntohs(header->h_proto);
}

static void GetEthProtocolStr(unsigned short protocol, char *str) {
  switch (protocol) {
    case ETH_P_LOOPBACK: {
      strcpy(str, "Ethernet Loopback");
      break;
    }
    case ETH_P_IP: {
      strcpy(str, "IPv4");
      break;
    }
    case ETH_P_ARP: {
      strcpy(str, "ARP");
      break;
    }
    case ETH_P_8021Q: {
      strcpy(str, "802.1Q VLAN Extended Header");
      break;
    }
    case ETH_P_IPV6: {
      strcpy(str, "IPv6");
      break;
    }
    default: {
      sprintf(str, "0x%04X", protocol);
      break;
    }
  }
}

void PrintEtherHeader(const struct ethhdr *header) {
  int i;
  char protocol_str[64];

  printf("Ethernet header\n");
  printf("Destination MAC: ");
  for (i = 0; i < ETH_ALEN; i++) {
    printf("%02X", (unsigned int)header->h_dest[i]);
    if (i != (ETH_ALEN - 1)) printf(":");
  }
  printf(" source MAC: ");
  for (i = 0; i < ETH_ALEN; i++) {
    printf("%02X", (unsigned int)header->h_source[i]);
    if (i != (ETH_ALEN - 1)) printf(":");
  }
  GetEthProtocolStr(header->h_proto, protocol_str);
  printf(" protocol: %s\n", protocol_str);
}

void GetIPv4Header(const unsigned char *packet, struct IPv4Header *ip_header) {
  int i;

  memcpy(&ip_header->header, packet, sizeof(struct iphdr));
  ip_header->header.tot_len = ntohs(ip_header->header.tot_len);
  ip_header->header.id = ntohs(ip_header->header.id);
  ip_header->header.frag_off = ntohs(ip_header->header.frag_off);
  ip_header->header.check = ntohs(ip_header->header.check);
  ip_header->header.saddr = ntohl(ip_header->header.saddr);
  ip_header->header.daddr = ntohl(ip_header->header.daddr);

  if (ip_header->header.ihl > 5) {
    ip_header->opt_length = ip_header->header.ihl - 5;
  } else {
    ip_header->opt_length = 0;
  }
  for (i = 0; i < ip_header->opt_length; i++) {
    ip_header->options[i] = *(uint32_t*)(packet + sizeof(*ip_header));
    ip_header->options[i] = ntohl(ip_header->options[i]);
  }
}

void IPAdressToStr(uint32_t addr, char *str) {
  unsigned int bytes[8];
  bytes[0] = addr & 0xFF;
  bytes[1] = (addr >> 8) & 0xFF;
  bytes[2] = (addr >> 16) & 0xFF;
  bytes[3] = (addr >> 24) & 0xFF;
  sprintf(str, "%u.%u.%u.%u", bytes[3], bytes[2], bytes[1], bytes[0]);
}

static void GetIPProtocolStr(unsigned char protocol, char *str) {
  switch (protocol) {
    case IPV4_PROT_ICMP: {
      strcpy(str, "ICMP");
      break;
    }
    case IPV4_PROT_TCP: {
      strcpy(str, "TCP");
      break;
    }
    case IPV4_PROT_UDP: {
      strcpy(str, "ICMP");
      break;
    }
    case IPV4_PROT_ENCAP: {
      strcpy(str, "IPv6 encapsulation");
      break;
    }
    case IPV4_PROT_SCTP: {
      strcpy(str, "SCTP");
      break;
    }
    default: {
      sprintf(str, "0x%02X", (int)protocol);
      break;
    }
  }
}

void PrintIPv4Header(const struct IPv4Header *ip_header) {
  char dest_str[32], source_str[32], prot_str[32];

  IPAdressToStr(ip_header->header.daddr, dest_str);
  IPAdressToStr(ip_header->header.saddr, source_str);

  printf("IPv4 header\n");
  printf("Destination IP: %s source IP: %s\n", dest_str, source_str);
  printf("Version: %d IHL: %d", (int)ip_header->header.version,
         (int)ip_header->header.ihl);
  printf(" identifiaction %hX", ip_header->header.id);
  printf(" time to live %d\n", (int)ip_header->header.ttl);
  GetIPProtocolStr(ip_header->header.protocol, prot_str);
  printf("Protocol %s. Total length %hu\n", prot_str, ip_header->header.tot_len);
}

int GetAllHeaders(const unsigned char *packet, struct UniHeader *headers) {
  int cnt = 0;

  return cnt;
}