#include "crc.h"

uint16_t CRC16Network(const unsigned char *data, int length, uint16_t acc) {
  int i;
  uint16_t dummy;
  uint32_t sum = acc;

  for (i = 0; i < length; i += 2) {
    sum += ntohs(*((uint16_t*)(data + i)));
  }
  if ((length % 2) != 0) {
    dummy = ((uint16_t)data[length - 1]) << 8;
    sum += ntohs(dummy);
  }
  sum = (sum >> 16) + (sum & 0xFFFF);
  sum = (sum >> 16) + (sum & 0xFFFF);
  return (uint16_t)sum;
}

uint16_t CRC16IPv4(const unsigned char *data, int length) {
  int acc;
  static const int kCheckPos = 10;
  static const int kNextPos = 12;

  acc = CRC16Network(data, kCheckPos, 0);
  acc = CRC16Network(data + kNextPos, length - kNextPos, acc);
  return ~acc;
}

uint16_t CRC16ICMP(const unsigned char *data, int length) {
  int acc;

  acc = CRC16Network(data, 2, 0);
  acc = CRC16Network(data + 4, length - 4, acc);
  return ~acc;
}

uint16_t CRC16TCP(const unsigned char *data, int length,
                  const unsigned char *pseudo) {
  int acc;
  static const int kCheckPos = 16;
  static const int kNextPos = 18;
  static const int kPseudoSize = 12;

  acc = CRC16Network(pseudo, kPseudoSize, 0);
  acc = CRC16Network(data, kCheckPos, acc);
  acc = CRC16Network(data + kNextPos, length - kNextPos, acc);
  return ~acc;
}