#include "print_packet.h"

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

static void PrintAddrStr(const unsigned char *data, int length) {
  int i;

  for (i = 0; i < length; i++) {
    printf("%02hhX", data[i]);
    if (i != (length - 1)) printf(":");
  }
}

static void PrintMAC(const unsigned char *data) {
  PrintAddrStr(data, ETH_ALEN);
}

static void IPAdressToStr(uint32_t addr, char *str) {
  unsigned int bytes[8];
  bytes[0] = addr & 0xFF;
  bytes[1] = (addr >> 8) & 0xFF;
  bytes[2] = (addr >> 16) & 0xFF;
  bytes[3] = (addr >> 24) & 0xFF;
  sprintf(str, "%u.%u.%u.%u", bytes[3], bytes[2], bytes[1], bytes[0]);
}

static void PrintEtherHeader(const struct ethhdr *header) {
  char protocol_str[PROTOCOL_STR_SIZE];

  printf("Ethernet header\n");
  printf("Destination MAC: ");
  PrintMAC(header->h_dest);
  printf(" source MAC: ");
  PrintMAC(header->h_source);
  GetEthProtocolStr(header->h_proto, protocol_str);
  printf(" protocol: %s\n", protocol_str);
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

static void PrintIPv4Header(const struct IPv4Header *ip_header) {
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

static void PrintProtocolAdress(const unsigned char *addr, int length) {
  char ip_str[32];

  if (length == 4) {
    IPAdressToStr(htonl(*((unsigned int*)addr)), ip_str);
    printf("%s", ip_str);
  }
  else {
    printf("unknown address type");
  }
}

static void PrintARPHeader(const struct ARPHeader *header) {
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

static void PrintICMPHeader(const struct ICMPHeader *header) {
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

static void PrintTCPHeader(const struct TCPHeader *tcp_header) {
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

static void PrintUDPHeader(const struct UDPHeader *udp_header) {
  printf("UDP packet\n");
  printf("Destination port: %hu ", udp_header->header.dest);
  printf("source port: %hu\n", udp_header->header.source);
  printf("Length: %hu\n", udp_header->header.len);
}

static void PrintChecksum(const struct UniHeader *header) {
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