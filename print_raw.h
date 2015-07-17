#ifndef SNIFFER_PRINT_RAW_H_
#define SNIFFER_PRINT_RAW_H_

#include <stdio.h>

extern void PrintRawChunk(int pos, const unsigned char *data, int length,
                          int tab);
extern void PrintRawData(const void *data, int length);

#endif // SNIFFER_PRINT_RAW_H_