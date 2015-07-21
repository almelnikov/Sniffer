#ifndef SNIFFER_CRC_H_
#define SNIFFER_CRC_H_

#include <arpa/inet.h>
#include <stdint.h>

#define IPV4_PSEUDOHDR_SIZE 12

extern uint16_t CRC16Network(const unsigned char *data, int length,
                             uint16_t acc);
extern uint16_t CRC16IPv4(const unsigned char *data, int length);
extern uint16_t CRC16ICMP(const unsigned char *data, int length);
extern uint16_t CRC16TCP(const unsigned char *data, int length,
                         const unsigned char *pseudo);
extern uint16_t CRC16UDP(const unsigned char *data, int length,
                         const unsigned char *pseudo);

#endif // SNIFFER_CRC_H_