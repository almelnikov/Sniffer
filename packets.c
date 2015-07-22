#include "packets.h"

static void GetEtherHeader(const unsigned char *packet, struct ethhdr *header) {
  memcpy(header, packet, sizeof(*header));  // Packed struct
  header->h_proto = ntohs(header->h_proto);
}

static int GetIPv4Header(const unsigned char *packet, int length,
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

static int GetARPHeader(const unsigned char *packet, int length,
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

static void FreeARPHeader(const struct ARPHeader *header) {
  free(header->ptr);
}

static int GetICMPHeader(const unsigned char *packet, int length,
                  struct ICMPHeader *header) {
  if (length < ICMP_HDR_SIZE) return -1;
  header->type = packet[0];
  header->code = packet[1];
  header->check = ntohs(*((uint16_t*)(packet + 2)));
  return 0;
}

static int GetTCPHeader(const unsigned char *packet, int length,
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

static int GetUDPHeader(const unsigned char *packet, int length,
                  struct UDPHeader *udp_header) {
  if (length < IPV4_HDR_RSIZE) return -1;
  memcpy(&udp_header->header, packet, sizeof(struct udphdr));
  udp_header->header.source = ntohs(udp_header->header.source);
  udp_header->header.dest = ntohs(udp_header->header.dest);
  udp_header->header.len = ntohs(udp_header->header.len);
  udp_header->header.check = ntohs(udp_header->header.check);
  return 0;
}

static void FormPseudoHeader(const struct IPv4Header *ip_hdr, uint16_t length,
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

static int GetOverIPHeader(const unsigned char *packet, int length, int protocol,
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
      header->load_length = udp_hdr_ptr->header.len - UDP_HDR_SIZE;
      FormPseudoHeader(ip_hdr, udp_hdr_ptr->header.len, udp_hdr_ptr->pseudo);
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

void ReallocateHeaders(const struct UniHeader *headers, int cnt) {
  int i;

  for (i = 0; i < cnt; i++) {
    if (headers[i].type == HDR_TYPE_ARP) {
      FreeARPHeader(&headers[i].header.arp);
    }
  }
}