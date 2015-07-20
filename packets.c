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

void PrintAddrStr(const unsigned char *data, int length) {
  int i;

  for (i = 0; i < length; i++) {
    printf("%02hhX", data[i]);
    if (i != (length - 1)) printf(":");
  }
}

void PrintMAC(const unsigned char *data) {
  PrintAddrStr(data, ETH_ALEN);
}

void PrintEtherHeader(const struct ethhdr *header) {
  char protocol_str[PROTOCOL_STR_SIZE];

  printf("Ethernet header\n");
  printf("Destination MAC: ");
  PrintMAC(header->h_dest);
  printf(" source MAC: ");
  PrintMAC(header->h_source);
  GetEthProtocolStr(header->h_proto, protocol_str);
  printf(" protocol: %s\n", protocol_str);
}

int GetIPv4Header(const unsigned char *packet, int length, struct IPv4Header *ip_header) {
  int i;

  if (length < IPV4_HDR_RSIZE) return -1;
  memcpy(&ip_header->header, packet, sizeof(struct iphdr));
  ip_header->header.tot_len = ntohs(ip_header->header.tot_len);
  ip_header->header.id = ntohs(ip_header->header.id);
  ip_header->header.frag_off = ntohs(ip_header->header.frag_off);
  ip_header->header.check = ntohs(ip_header->header.check);
  ip_header->header.saddr = ntohl(ip_header->header.saddr);
  ip_header->header.daddr = ntohl(ip_header->header.daddr);

  if (length < ip_header->header.ihl * 4) return -1;
  if (ip_header->header.ihl > 5) {
    ip_header->opt_length = ip_header->header.ihl - 5;
  } else {
    ip_header->opt_length = 0;
  }
  for (i = 0; i < ip_header->opt_length; i++) {
    ip_header->options[i] = *(uint32_t*)(packet + sizeof(*ip_header));
    ip_header->options[i] = ntohl(ip_header->options[i]);
  }
  return 0;
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

int GetARPHeader(const unsigned char *packet, int length, struct ARPHeader *header) {
  int addrs_size;

  if (length < ARP_HDR_RSIZE) return -1;
  memcpy(header, packet, ARP_HDR_RSIZE);
  header->htype = htons(header->htype);
  header->ptype = htons(header->ptype);
  header->oper = htons(header->oper);
  addrs_size = 2 * ((int)header->hlen + (int)header->plen);
  if (length < (ARP_HDR_RSIZE + addrs_size)) return -1;
  header->ptr = malloc(addrs_size);
  if (header->ptr == NULL) {
    fprintf(stderr, "Cannot allocate memory in function GetARPHeader\n");
    exit(-1);
  }
  memcpy(header->ptr, packet + ARP_HDR_RSIZE, addrs_size);
  return 0;
}

void FreeARPHeader(struct ARPHeader *header) {
  free(header->ptr);
}

void PrintProtocolAdress(const unsigned char *addr, int length) {
  char ip_str[32];

  if (length == 4) {
    IPAdressToStr(htonl(*((unsigned int*)addr)), ip_str);
    printf("%s", ip_str);
  }
  else {
    printf("unknown address type");
  }
}

void PrintARPHeader(const struct ARPHeader *header) {
  char protocol_str[PROTOCOL_STR_SIZE];
  unsigned char *sender_hard = header->ptr;
  unsigned char *sender_prot = header->ptr + (int)header->hlen;
  unsigned char *target_hard = header->ptr + (int)header->hlen + (int)header->plen;
  unsigned char *target_prot = header->ptr + 2 * (int)header->hlen + (int)header->plen;

  printf("ARP header\n");
  GetEthProtocolStr(header->ptype, protocol_str);
  printf("Hardware type 0x%04hX, Protocol %s\n", header->htype, protocol_str);
  printf("Hardware address length:%hhu ", header->hlen);
  printf("protocol address length:%hhu ", header->plen);
  if (header->oper == ARP_PROT_REQUEST) {
    printf("Request\n");
  } else if (header->oper == ARP_PROT_REPLY) {
    printf("Reply\n");
  } else {
    printf("operation %04hX\n", header->oper);
  }
  printf("Sender hardware address: ");
  PrintAddrStr(sender_hard, header->hlen);
  printf(" sender protocol address: ");
  PrintProtocolAdress(sender_prot, header->plen);
  printf("\n");
  printf("Target hardware address: ");
  PrintAddrStr(target_hard, header->hlen);
  printf(" target protocol address: ");
  PrintProtocolAdress(target_prot, header->plen);
  printf("\n");
}

/*
int GetAllHeaders(const unsigned char *packet, int length, struct UniHeader *headers) {
  int cnt = 0;
  const unsigned char *eth_hdr_end;
  struct ethhdr eth_header;
  struct IPv4Header ipv4_header;
  struct ARPHeader arp_header;

  GetEtherHeader(packet, &eth_header);
  eth_hdr_end = packet + sizeof(eth_header);
  headers[0].type = HDR_TYPE_ETH;
  headers[0].header.eth = eth_header;
  headers[0].load_begin = eth_hdr_end;
  headers[0].load_end = packet + length;  // ?

  return cnt;
}
*/