#include<stdio.h>
#include<stdlib.h>
#include<ctype.h>
#include"hexdump.h"
#include"icmpRead.h"

void ICMPinfo(unsigned char *data,int size)
{
    int index;
    unsigned char typeArray[2];
    int typeIndex;

    // Ethernet Part - Destination MAC Address (Bytes 0 to 5)
    for(index=0;index<6;index++)
    {
        unsigned char currentByte;
        currentByte=data[index];
        printf("%02X ",currentByte);
    }
    printf("\n");

    // Ethernet Part - Source MAC Address (Bytes 6 to 11)
    for(index=6;index<12;index++)
    {
        unsigned char currentByte;
        currentByte=data[index];
        printf("%02X ",currentByte);
    }
    printf("\n");

    // Ethernet Part - Ethernet Type (Bytes 12 to 13)
    typeIndex=0;
    for(index=12;index<14;index++)
    {
        unsigned char currentByte;
        currentByte=data[index];
        typeArray[typeIndex]=currentByte;
        typeIndex++;
        printf("%02X ",currentByte);
    }
    IPtype(typeArray);
    printf("\n");

    // IP Part - Type of Service / DSCP (Byte 15)
    // Note: Original code skipped byte 14, keeping the same logic
    unsigned char tosByte;
    tosByte=data[15];
    printf("%02X\n",tosByte);

    // IP Part - Total Length (Bytes 16 to 17)
    for(index=16;index<18;index++)
    {
        unsigned char currentByte;
        currentByte=data[index];
        printf("%02X ",currentByte);
    }
    printf("\n");

    // IP Part - Identification (Bytes 18 to 19)
    for(index=18;index<20;index++)
    {
        unsigned char currentByte;
        currentByte=data[index];
        printf("%02X ",currentByte);
    }
    printf("\n");

    // IP Part - Flags (Byte 20)
    unsigned char flagsByte;
    flagsByte=data[20];
    printf("%d\n",flagsByte);

    // IP Part - Fragment Offset (Byte 21)
    unsigned char fragOffsetByte;
    fragOffsetByte=data[21];
    printf("%d\n",fragOffsetByte);

    // IP Part - Time to Live / TTL (Byte 22)
    unsigned char ttlByte;
    ttlByte=data[22];
    printf("%d\n",ttlByte);

    // IP Part - Protocol (Byte 23)
    unsigned char protocolByte;
    protocolByte=data[23];
    
    if(protocolByte==1)
        printf("1\n");

    // IP Part - Header Checksum (Bytes 24 to 25)
    for(index=24;index<26;index++)
    {
        unsigned char currentByte;
        currentByte=data[index];
        printf("%02X ",currentByte);
    }
    printf("\n");

    // IP Part - Source IP Address (Bytes 26 to 29)
    for(index=26;index<30;index++)
    {
        unsigned char currentByte;
        currentByte=data[index];
        printf("%d",currentByte);
        
        if(index!=29)
            printf(".");
    }
    printf("\n");

    // IP Part - Destination IP Address (Bytes 30 to 33)
    for(index=30;index<34;index++)
    {
        unsigned char currentByte;
        currentByte=data[index];
        printf("%d",currentByte);
        
        if(index!=33)
            printf(".");
    }
    printf("\n");

    // ICMP Part - Type (Byte 34)
    unsigned char icmpType;
    icmpType=data[34];
    printf("%d\n",icmpType);

    // ICMP Part - Code (Byte 35)
    unsigned char icmpCode;
    icmpCode=data[35];
    printf("%d\n",icmpCode);

    // ICMP Part - Checksum (Bytes 36 to 37)
    for(index=36;index<38;index++)
    {
        unsigned char currentByte;
        currentByte=data[index];
        printf("%02X ",currentByte);
    }
    printf("\n");

    // ICMP Part - Identifier (Bytes 38 to 39)
    for(index=38;index<40;index++)
    {
        unsigned char currentByte;
        currentByte=data[index];
        printf("%02X ",currentByte);
    }
    printf("\n");

    // ICMP Part - Sequence Number (Bytes 40 to 41)
    for(index=40;index<42;index++)
    {
        unsigned char currentByte;
        currentByte=data[index];
        printf("%02X ",currentByte);
    }
    printf("\n");

    // ICMP Part - Payload Timestamp/Data (Bytes 42 to 49)
    for(index=42;index<50;index++)
    {
        unsigned char currentByte;
        currentByte=data[index];
        printf("%02X ",currentByte);
    }
    printf("\n");

    // ICMP Part - Rest of the Payload (Byte 50 to end)
    for(index=50;index<size;index++)
    {
        unsigned char currentByte;
        currentByte=data[index];
        printf("%02X ",currentByte);
    }
    printf("\n");
}

void IPtype(unsigned char *type)
{
    unsigned char typeByteOne;
    typeByteOne=type[0];
    
    unsigned char typeByteTwo;
    typeByteTwo=type[1];
    
    if(typeByteOne==8 && typeByteTwo==0)
        printf(" IPv4");
}

void packettype(unsigned char *type)
{
    unsigned char typeByteOne;
    typeByteOne=type[0];
    
    unsigned char typeByteTwo;
    typeByteTwo=type[1];
    
    if(typeByteOne==8 && typeByteTwo==6)
        printf(" ARP");
}

void hardwaretype(unsigned char *type)
{
    unsigned char typeByteOne;
    typeByteOne=type[0];
    
    unsigned char typeByteTwo;
    typeByteTwo=type[1];
    
    if(typeByteOne==0 && typeByteTwo==1)
        printf(" ETHERNET");
}

void protocoltype(unsigned char *type)
{
    unsigned char typeByteOne;
    typeByteOne=type[0];
    
    unsigned char typeByteTwo;
    typeByteTwo=type[1];
    
    if(typeByteOne==8 && typeByteTwo==0)
        printf(" IPv4");
}