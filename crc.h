#ifndef SNIFFER_CRC_H_
#define SNIFFER_CRC_H_

#include <arpa/inet.h>
#include <stdint.h>

extern uint16_t CRC16Network(const unsigned char *data, int length,
                             uint16_t acc);
extern uint16_t CRC16IPv4(const unsigned char *data, int length);

#endif // SNIFFER_CRC_H_