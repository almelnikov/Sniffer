#include "packets.h"

void GetEtherHeader(const unsigned char *packet, struct ethhdr *header)
{
  memcpy(header, packet, sizeof(struct ethhdr));  // Packed struct
  header->h_proto = ntohs(header->h_proto);
}

static void GetProtocolStr(unsigned short protocol, char *str)
{
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
      sprintf(str, "0x%X", protocol);
      break;
    }
  }
}

void PrintEtherHeader(struct ethhdr *header)
{
  int i;
  char protocol_str[64];

  printf("Dest MAC: ");
  for (i = 0; i < ETH_ALEN; i++) {
    printf("%02X", (unsigned int)header->h_dest[i]);
    if (i != (ETH_ALEN - 1)) printf(":");
  }
  printf(" source MAC: ");
  for (i = 0; i < ETH_ALEN; i++) {
    printf("%02X", (unsigned int)header->h_source[i]);
    if (i != (ETH_ALEN - 1)) printf(":");
  }
  GetProtocolStr(header->h_proto, protocol_str);
  printf(" protocol: %s\n", protocol_str);
}