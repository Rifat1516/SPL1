CC = gcc
CFLAGS = -Wall -I.
LIBS = -lpcap
TARGET = PackAnalyzer


SRCS = argdump.c Realtimepacket.c analyzer.c

all: $(TARGET)

$(TARGET): $(SRCS)
	$(CC) $(CFLAGS) $(SRCS) -o $(TARGET) $(LIBS)

clean:
	rm -f $(TARGET) PacketInfo.txt
