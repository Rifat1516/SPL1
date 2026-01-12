CC = gcc
CFLAGS = -Wall -I.
LIBS = -lpcap
TARGET = PacketEye
SRCS = argdump.c Realtimepacket.c SynFlood.c arpRead.c dumpingfunc.c hexdump.c icmpRead.c

all: $(TARGET)

$(TARGET): $(SRCS)
	$(CC) $(CFLAGS) $(SRCS) -o $(TARGET) $(LIBS)

clean:
	rm -f $(TARGET)