#include "packets.h"

void GetEtherHeader(const unsigned char *packet, struct ethhdr *header) {
  memcpy(header, packet, sizeof(*header));  // Packed struct
  header->h_proto = ntohs(header->h_proto);
}

static void GetEthProtocolStr(unsigned short protocol, char *str) {
  switch (protocol) {
    case ETH_P_LOOP: {
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

int GetIPv4Header(const unsigned char *packet, int length,
                  struct IPv4Header *ip_header) {
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
    ip_header->options[i] = *(uint32_t*)(packet + IPV4_HDR_RSIZE + i*4);
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

int GetARPHeader(const unsigned char *packet, int length,
                 struct ARPHeader *header) {
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

int GetICMPHeader(const unsigned char *packet, int length,
                  struct ICMPHeader *header) {
  if (length < ICMP_HDR_SIZE) return -1;
  header->type = packet[0];
  header->code = packet[1];
  header->check = ntohs(*((uint16_t*)(packet + 2)));
  return 0;
}

void PrintICMPHeader(const struct ICMPHeader *header) {
  uint16_t id, seq_num;

  id = header->data && 0xFFFF;
  seq_num = header->data >> 16;
  if (header->type == 0 && header->code == 0) {
    printf("ECHO Reply\n");
    printf("Identifier: %hX Sequence Number: %hX", id, seq_num);
  }
  if (header->type == 8 && header->code == 0) {
    printf("ECHO Request\n");
  } else {
    printf("Type: %hhX Code: %hhX\n", header->type, header->code);
    printf("Header data: %X\n", header->data);
  }
}

int GetTCPHeader(const unsigned char *packet, int length,
                  struct TCPHeader *tcp_header) {
  int i;

  if (length < IPV4_HDR_RSIZE) return -1;
  memcpy(&tcp_header->header, packet, sizeof(struct tcphdr));
  tcp_header->header.source = ntohs(tcp_header->header.source);
  tcp_header->header.dest = ntohs(tcp_header->header.dest);
  tcp_header->header.seq = ntohl(tcp_header->header.seq);
  tcp_header->header.ack_seq = ntohl(tcp_header->header.ack_seq);
  tcp_header->header.window = ntohs(tcp_header->header.window);
  tcp_header->header.check = ntohs(tcp_header->header.check);
  tcp_header->header.urg_ptr = ntohs(tcp_header->header.urg_ptr);

  if (length < tcp_header->header.doff * 4) return -1;
  if (tcp_header->header.doff > 5) {
    tcp_header->opt_length = tcp_header->header.doff - 5;
  } else {
    tcp_header->opt_length = 0;
  }
  for (i = 0; i < tcp_header->opt_length; i++) {
    tcp_header->options[i] = *(uint32_t*)(packet + TCP_HDR_RSIZE + i*4);
    tcp_header->options[i] = ntohl(tcp_header->options[i]);
  }
  return 0;
}

void PrintTCPHeader(const struct TCPHeader *tcp_header) {
  printf("TCP packet\n");
  printf("Destination port: %hu ", tcp_header->header.dest);
  printf("source port: %hu\n", tcp_header->header.source);
  printf("Sequence number: 0x%X ", tcp_header->header.seq);
  printf("acknowledgment number: 0x%X\n", tcp_header->header.ack_seq);
  printf("Window size: %hu ", tcp_header->header.window);
  printf("urgent pointer: %hu\n", tcp_header->header.urg_ptr);
  // print flags
  printf("Data offset: %hu ", tcp_header->header.doff);
  printf("CWR: %hu ", tcp_header->header.cwr);
  printf("ECE: %hu ", tcp_header->header.ece);
  printf("URG: %hu\n", tcp_header->header.urg);
  printf("ACK: %hu ", tcp_header->header.ack);
  printf("PSH: %hu ", tcp_header->header.psh);
  printf("RST: %hu ", tcp_header->header.rst);
  printf("SYN: %hu ", tcp_header->header.syn);
  printf("FIN: %hu\n", tcp_header->header.fin);
}

void PrintUDPHeader(const struct UDPHeader *udp_header) {
  printf("UDP packet\n");
  printf("Destination port: %hu ", udp_header->header.dest);
  printf("source port: %hu\n", udp_header->header.source);
  printf("Length: %hu\n", udp_header->header.len);
}

int GetUDPHeader(const unsigned char *packet, int length,
                  struct UDPHeader *udp_header) {
  if (length < IPV4_HDR_RSIZE) return -1;
  memcpy(&udp_header->header, packet, sizeof(struct udphdr));
  udp_header->header.source = ntohs(udp_header->header.source);
  udp_header->header.dest = ntohs(udp_header->header.dest);
  udp_header->header.len = ntohs(udp_header->header.len);
  udp_header->header.check = ntohs(udp_header->header.check);
  return 0;
}

void PrintChecksum(const struct UniHeader *header) {
  uint16_t packet_crc, calc_crc;
  int flag_print = 0;
  int length;

  length = (header->load_begin - header->hdr_begin) + header->load_length;
  //printf("Checksum length = %d\n", length);
  switch (header->type) {
    case HDR_TYPE_IPV4: {
      packet_crc = header->header.ipv4.header.check;
      calc_crc = CRC16IPv4(header->hdr_begin,
                           header->header.ipv4.header.ihl * 4);
      flag_print = 1;
      break;
    }
    case HDR_TYPE_TCP: {
      packet_crc = header->header.tcp.header.check;
      calc_crc = CRC16TCP(header->hdr_begin, length, header->header.tcp.pseudo);
      flag_print = 1;
      break;
    }
    case HDR_TYPE_UDP: {
      packet_crc = header->header.udp.header.check;
      calc_crc = CRC16UDP(header->hdr_begin, length, header->header.udp.pseudo);
      flag_print = 1;
      break;
    }
    case HDR_TYPE_ICMP: {
      packet_crc = header->header.icmp.check;
      calc_crc = CRC16ICMP(header->hdr_begin, length);
      flag_print = 1;
      break;
    }
    case HDR_TYPE_ARP:
    case HDR_TYPE_ETH:
    case HDR_TYPE_ERROR: {
      break;
    }
  }
  if (flag_print) {
    if (packet_crc == calc_crc) {
      printf("Correct checksum = 0x%04hX\n", packet_crc);
    }
    else {
      printf("Packet checkum = 0x%04hX, expectable checksum = 0x%04hX\n",
             packet_crc, calc_crc);
    }
  }
}

void PrintHeader(const struct UniHeader *header) {
  switch (header->type) {
    case HDR_TYPE_ETH: {
      PrintEtherHeader(&header->header.eth);
      break;
    }
    case HDR_TYPE_IPV4: {
      PrintIPv4Header(&header->header.ipv4);
      break;
    }
    case HDR_TYPE_ARP: {
      PrintARPHeader(&header->header.arp);
      break;
    }
    case HDR_TYPE_ICMP: {
      PrintICMPHeader(&header->header.icmp);
      break;
    }
    case HDR_TYPE_TCP: {
      PrintTCPHeader(&header->header.tcp);
      break;
    }
    case HDR_TYPE_UDP: {
      PrintUDPHeader(&header->header.udp);
      break;
    }
    case HDR_TYPE_ERROR: {
      printf("Packet have size less than header field\n");
      break;
    }
  }
  PrintChecksum(header);
}

void FormPseudoHeader(const struct IPv4Header *ip_hdr, uint16_t length,
                      unsigned char *pseudo) {
    uint32_t netip;
    uint16_t netlen;

    netip = htonl(ip_hdr->header.saddr);
    memcpy(pseudo, &netip, 4);
    netip = htonl(ip_hdr->header.daddr);
    memcpy(pseudo + 4, &netip, 4);
    pseudo[8] = 0;
    pseudo[9] = ip_hdr->header.protocol;
    netlen = htons(length);
    memcpy(pseudo + 10, &netlen, 2);
}

int GetOverIPHeader(const unsigned char *packet, int length, int protocol,
                    const struct IPv4Header *ip_hdr, struct UniHeader *header) {
  struct ICMPHeader *icmp_hdr_ptr;
  struct TCPHeader *tcp_hdr_ptr;
  struct UDPHeader *udp_hdr_ptr;
  int ret;
  uint16_t tcp_length;

  header->type = HDR_TYPE_ERROR;
  header->hdr_begin = packet;
  tcp_length = ip_hdr->header.tot_len - ip_hdr->header.ihl * 4;
  if (protocol == IPV4_PROT_ICMP) {
    icmp_hdr_ptr = &header->header.icmp;
    ret = GetICMPHeader(packet, length, icmp_hdr_ptr);
    if (ret == 0) {
      header->type = HDR_TYPE_ICMP;
      header->load_begin = packet + ICMP_HDR_SIZE;
      header->load_length = length - ICMP_HDR_SIZE;
    } else return -1;
  } else if (protocol == IPV4_PROT_TCP) {
    tcp_hdr_ptr = &header->header.tcp;
    ret = GetTCPHeader(packet, length, tcp_hdr_ptr);
    if (ret == 0) {
      //printf("TCP = %hu RAW = %d\n", tcp_length, length);
      header->type = HDR_TYPE_TCP;
      header->load_begin = packet + tcp_hdr_ptr->header.doff * 4;
      //header->load_length = length - tcp_hdr_ptr->header.doff * 4;
      header->load_length = tcp_length - tcp_hdr_ptr->header.doff * 4;
      FormPseudoHeader(ip_hdr, tcp_length, tcp_hdr_ptr->pseudo);
    } else return -1;
  } else if (protocol == IPV4_PROT_UDP) {
    udp_hdr_ptr = &header->header.udp;
    ret = GetUDPHeader(packet, length, udp_hdr_ptr);
    if (ret == 0) {
      header->type = HDR_TYPE_UDP;
      header->load_begin = packet + UDP_HDR_SIZE;
      header->load_length = length - udp_hdr_ptr->header.len;
      FormPseudoHeader(ip_hdr, header->load_length + UDP_HDR_SIZE,
                       udp_hdr_ptr->pseudo);
    } else return -1;
  }
  return 0;
}

int GetAllHeaders(const unsigned char *packet, int length,
                  struct UniHeader *headers) {
  int cnt = 0;
  int ret, no_eth_length;
  int ipv4_packet_size;
  const unsigned char *eth_hdr_end;
  struct ethhdr eth_header;
  struct IPv4Header *ipv4_hdr_ptr;
  struct ARPHeader *arp_hdr_ptr;

  if (length < sizeof(eth_header)) return 0;
  GetEtherHeader(packet, &eth_header);
  eth_hdr_end = packet + sizeof(eth_header);
  no_eth_length = length - sizeof(eth_header);
  headers[0].type = HDR_TYPE_ETH;
  headers[0].header.eth = eth_header;
  headers[0].hdr_begin = packet;
  headers[0].load_begin = eth_hdr_end;
  headers[0].load_length = no_eth_length;
  cnt = 2;  // can't read => write HDR_TYPE_ERROR to headers[1].type
  headers[1].hdr_begin = eth_hdr_end;
  if (eth_header.h_proto == ETH_P_IP) {
    ipv4_hdr_ptr = &headers[1].header.ipv4;
    ret = GetIPv4Header(eth_hdr_end, no_eth_length, ipv4_hdr_ptr);
    if (ret == 0) {
      headers[1].type = HDR_TYPE_IPV4;
      ipv4_packet_size = ipv4_hdr_ptr->header.ihl * 4;
      headers[1].load_begin = eth_hdr_end + ipv4_packet_size;
      headers[1].load_length = no_eth_length - ipv4_packet_size;
      ret = GetOverIPHeader(headers[1].load_begin, headers[1].load_length,
                            ipv4_hdr_ptr->header.protocol, ipv4_hdr_ptr,
                            &headers[2]);
      if (ret == 0) cnt++;
    } else {
      headers[1].type = HDR_TYPE_ERROR;
    }
  } else if (eth_header.h_proto == ETH_P_ARP) {
    arp_hdr_ptr = &headers[1].header.arp;
    ret = GetARPHeader(eth_hdr_end, no_eth_length, arp_hdr_ptr);
    if (ret == 0) {
      headers[1].type = HDR_TYPE_ARP;
      headers[1].load_begin = 0;
      headers[1].load_length = 0;
    } else {
      headers[1].type = HDR_TYPE_ERROR;
    }
  }

  return cnt;
}
