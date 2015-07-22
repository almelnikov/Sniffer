#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <time.h>
#include <stdint.h>
#include <pcap/pcap.h>
#include "print_raw.h"
#include "packets.h"
#include "print_packet.h"

#define INTERFACE_STR_SIZE 256
#define ERROR_HDR_SIZE 1
#define ERROR_CHECKSUM 2

struct GetterParams {
  char flag_e;
  char flag_r;
  char flag_I;
  char flag_A;
  char flag_C;
  char flag_T;
  char flag_U;
  char flag_a;
};

int CheckContainIPv4(const struct UniHeader *headers, int cnt) {
  int result = 0;

  if (cnt >= 2) {
    if (headers[1].type == HDR_TYPE_IPV4) result = 1;
  }
  return result;
}

int CheckContainARP(const struct UniHeader *headers, int cnt) {
  int result = 0;

  if (cnt >= 2) {
    if (headers[1].type == HDR_TYPE_ARP) result = 1;
  }
  return result;
}

int CheckContainICMP(const struct UniHeader *headers, int cnt) {
  int result = 0;

  if (cnt >= 3) {
    if (headers[2].type == HDR_TYPE_ICMP) result = 1;
  }
  return result;
}

int CheckContainTCP(const struct UniHeader *headers, int cnt) {
  int result = 0;

  if (cnt >= 3) {
    if (headers[2].type == HDR_TYPE_TCP) result = 1;
  }
  return result;
}

int CheckContainUDP(const struct UniHeader *headers, int cnt) {
  int result = 0;

  if (cnt >= 3) {
    if (headers[2].type == HDR_TYPE_UDP) result = 1;
  }
  return result;
}

void GotPacket(u_char *args, const struct pcap_pkthdr *header,
     const u_char *packet) {
  char time_buf[64];
  struct tm *packet_time;
  struct GetterParams params = *(struct GetterParams*)args;
  time_t sec_time = header->ts.tv_sec;
  struct UniHeader headers[4];
  int cnt, i;
  int length = header->caplen;
  int print_flag = 0;
  int load_num = 0;

  cnt = GetAllHeaders(packet, length, headers);
  if (params.flag_I) {
    print_flag |= CheckContainIPv4(headers, cnt);
  }
  if (params.flag_A) {
    print_flag |= CheckContainARP(headers, cnt);
  }
  if (params.flag_C) {
    print_flag |= CheckContainICMP(headers, cnt);
  }
  if (params.flag_T) {
    print_flag |= CheckContainTCP(headers, cnt);
  }
  if (params.flag_U) {
    print_flag |= CheckContainUDP(headers, cnt);
  }
  if (params.flag_a) print_flag = 1;
  if (print_flag) {
    packet_time = localtime(&sec_time);
    printf("Recived packet, total length: %d\n", header->caplen);
    strftime(time_buf, sizeof(time_buf), "%Y-%m-%d %H:%M:%S", packet_time);
    printf("%s %06dusec\n", time_buf, (int)header->ts.tv_usec);
    if (params.flag_a) {
      for (i = 0; i < cnt; i++) {
        PrintHeader(&headers[i]);
      }
    } else {
      if (params.flag_e) {
        PrintHeader(&headers[0]);
      }
      if (params.flag_I || params.flag_A) {
        PrintHeader(&headers[1]);
      }
      if (params.flag_C || params.flag_T || params.flag_U) {
        PrintHeader(&headers[2]);
      }
    }
    if (params.flag_r) {
      printf("RAW packet\n");
      PrintRawData(packet, header->caplen);
    } else {
      printf("Payload\n");
      if (params.flag_I || params.flag_A) {
        load_num = 1;
      }
      if (params.flag_C || params.flag_T || params.flag_U) {
        load_num = 2;
      }
      PrintRawData(headers[load_num].load_begin,
                   headers[load_num].load_length);
    }
    printf("\n");
  }
  ReallocateHeaders(headers, cnt);
}

int main(int argc, char *argv[]) {
  pcap_t *handle_dev;
  char errbuf[PCAP_ERRBUF_SIZE];
  char interface_str[INTERFACE_STR_SIZE], *dev_str;
  int buffer_size = 10000;
  int repeat_cnt = 0;
  int opt, ret, opt_int;
  int flag_i = 0; // Use custom interface
  struct GetterParams getter_params;

  getter_params.flag_e = 0;
  getter_params.flag_r = 0;
  getter_params.flag_I = 0;
  getter_params.flag_A = 0;
  getter_params.flag_C = 0;
  getter_params.flag_T = 0;
  getter_params.flag_U = 0;
  getter_params.flag_a = 0;
  while ((opt = getopt(argc, argv, "erIACTUan:s:i:")) != -1) {
    switch (opt) {
      opt_int = 0;
      case 'e': {  // Print ethernet header
        getter_params.flag_e = 1;
        break;
      }
      case 'r': {  // Print raw data
        getter_params.flag_r = 1;
        break;
      }
      case 'I': {  // Print IPv4 headers
        getter_params.flag_I = 1;
        break;
      }
      case 'A': {  // Print ARP headers
        getter_params.flag_A = 1;
        break;
      }
      case 'C': {  // Print ICMP headers
        getter_params.flag_C = 1;
        break;
      }
      case 'T': {  // Print TCP headers
        getter_params.flag_T = 1;
        break;
      }
      case 'U': {  // Print UDP headers
        getter_params.flag_U = 1;
        break;
      }
      case 'a': {  // Print all packets
        getter_params.flag_a = 1;
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