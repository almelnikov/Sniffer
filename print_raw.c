#include "print_raw.h"

void PrintRawChunk(int pos, const unsigned char *data, int length, int tab) {
  int i;

  printf("%04d:  ", pos);
  for (i = 0; i < length; i++) {
    printf("%02X ", data[i]);
  }
  for ( ; i < tab; i++) {
    printf("   ");
  }
  printf(" %.*s\n", length, data);
}

void PrintRawData(const void *data, int length) {
  int i;

  for (i = 0; i < length; i += 16) {
    if (length - i < 16) {
      PrintRawChunk(i, data + i, length - i, 16);
    }
    else {
      PrintRawChunk(i, data + i, 16, 16);
    }
  }
}