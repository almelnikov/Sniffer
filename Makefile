CC=gcc
CFLAGS=-g2 -Wall

.PHONY: clean
.PHONY: all
all: sniffer

sniffer: main.o packets.o print_raw.o print_packet.o crc.o
	$(CC) $(CFLAGS) main.o packets.o print_raw.o print_packet.o crc.o -o sniffer -lpcap

main.o : main.c
	$(CC) $(CFLAGS) -c main.c

packets.o : packets.c
	$(CC) $(CFLAGS) -c packets.c

print_packet.o : print_packet.c
	$(CC) $(CFLAGS) -c print_packet.c

print_raw.o : print_raw.c
	$(CC) $(CFLAGS) -c print_raw.c

crc.o : crc.c
	$(CC) $(CFLAGS) -c crc.c

clean:
	rm -f *.o