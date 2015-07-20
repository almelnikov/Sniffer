#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <time.h>
#include <pcap/pcap.h>
#include "print_raw.h"
#include "packets.h"

#define INTERFACE_STR_SIZE 256

struct GetterParams {
  char flag_e;
  char flag_r;
  char flag_I;
  char flag_a;
};

void GotPacket(u_char *args, const struct pcap_pkthdr *header,
     const u_char *packet) {
  char time_buf[64];
  struct tm *packet_time;
  struct GetterParams *params = (struct GetterParams*)args;
  time_t sec_time = header->ts.tv_sec;
  struct ethhdr eth_header;
  struct IPv4Header ipv4_header;

  packet_time = localtime(&sec_time);
  strftime(time_buf, sizeof(time_buf), "%Y-%m-%d %H:%M:%S", packet_time);
  printf("%s %06dusec\n", time_buf, (int)header->ts.tv_usec);

  GetEtherHeader(packet, &eth_header);

  if (params->flag_e) {
    PrintEtherHeader(&eth_header);
    printf("\n");
  }
  if (params->flag_I && (eth_header.h_proto == ETH_P_IP)) {
    GetIPv4Header(packet + sizeof(eth_header), &ipv4_header);
    PrintIPv4Header(&ipv4_header);
    printf("\n");
  }
  if (params->flag_r) {
    PrintRawData(packet, header->caplen);
    printf("\n");
  }
}

int main(int argc, char *argv[]) {
  pcap_t *handle_dev;
  char errbuf[PCAP_ERRBUF_SIZE];
  char interface_str[INTERFACE_STR_SIZE], *dev_str;
  int buffer_size = 2048;
  int repeat_cnt = 1;
  int opt, ret, opt_int;
  int flag_e = 0; // Print ethernet header
  int flag_I = 0; // Print internet layer headers
  int flag_a = 0; // Print ARP headers
  int flag_r = 0; // Print raw data
  int flag_i = 0; // Use custom interface
  struct GetterParams getter_params;

  while ((opt = getopt(argc, argv, "erIn:s:i:")) != -1) {
    switch (opt) {
      opt_int = 0;
      case 'e': {  // Print ethernet header
        flag_e = 1;
        break;
      }
      case 'r': {  // Print raw data
        flag_r = 1;
        break;
      }
      case 'I': {  // Print IPv4 headers
        flag_I = 1;
        break;
      }
      case 'a': {  // Print ARP headers
        flag_a = 1;
        break;
      }
      case 'n': {  // Number of repeats
        ret = sscanf(optarg, "%d", &opt_int);
        if (ret == 1 && opt_int >= 0) {
            repeat_cnt = opt_int;
        } else {
            fprintf(stderr, "Wrong argunment after -n: %s\n", optarg);
        }
        break;
      }
      case 's': {  // Set packet buffer size
        ret = sscanf(optarg, "%d", &opt_int);
        if (ret == 1 && opt_int > 0) {
            buffer_size = opt_int;
        } else {
            fprintf(stderr, "Wrong argunment after -s: %s\n", optarg);
        }
        break;
      }
      case 'i': {  // Use custom interface
        flag_i = 1;
        strncpy(interface_str, optarg, INTERFACE_STR_SIZE);
        break;
      }
    }
  }

  getter_params.flag_e = flag_e;
  getter_params.flag_r = flag_r;
  getter_params.flag_I = flag_I;
  getter_params.flag_a = flag_a;

  if (flag_i == 0) {
    dev_str = pcap_lookupdev(errbuf);
    if (dev_str == NULL) {
      fprintf(stderr, "Couldn't find default device: %s\n", errbuf);
      return(-1);
    }
    strncpy(interface_str, dev_str, INTERFACE_STR_SIZE);
    printf("Using default interface: %s\n", interface_str);
  }

  handle_dev = pcap_open_live(interface_str, buffer_size, 0, 1000, errbuf);
  if (handle_dev == NULL) {
    fprintf(stderr, "Couldn't open device %s. %s\n", interface_str, errbuf);
    exit(-1);
  }
  pcap_loop(handle_dev, repeat_cnt, GotPacket, (u_char*)&getter_params);

  return 0;
}