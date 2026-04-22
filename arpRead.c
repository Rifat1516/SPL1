#include<stdio.h>
#include<stdlib.h>
#include<ctype.h>
#include"hexdump.h"
#include"icmpRead.h"
#include"arpRead.h"

void packetinfo(unsigned char *data,int size)
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
    packettype(typeArray);
    printf("\n");

    // Padding Check (Original Output Sequence Maintained)
    if(size>42)
    {
        int paddingIndex;
        for(paddingIndex=42;paddingIndex<size;paddingIndex++)
        {
            unsigned char currentByte;
            currentByte=data[paddingIndex];
            printf("%02X ",currentByte);
        }
        printf("\n\n");
    }

    // ARP Part - Hardware Type (Bytes 14 to 15)
    typeIndex=0;
    for(index=14;index<16;index++)
    {
        unsigned char currentByte;
        currentByte=data[index];
        typeArray[typeIndex]=currentByte;
        typeIndex++;
        printf("%02X ",currentByte);
    }
    hardwaretype(typeArray);
    printf("\n");

    // ARP Part - Protocol Type (Bytes 16 to 17)
    typeIndex=0;
    for(index=16;index<18;index++)
    {
        unsigned char currentByte;
        currentByte=data[index];
        typeArray[typeIndex]=currentByte;
        typeIndex++;
        printf("%02X ",currentByte);
    }
    protocoltype(typeArray);
    printf("\n");

    // ARP Part - Hardware Size (Byte 18)
    unsigned char hardwareSize;
    hardwareSize=data[18];
    printf("%d\n",hardwareSize);

    // ARP Part - Protocol Size (Byte 19)
    unsigned char protocolSize;
    protocolSize=data[19];
    printf("%d\n",protocolSize);

    // ARP Part - Opcode (Bytes 20 to 21)
    unsigned char opcodeByteOne;
    opcodeByteOne=data[20];
    printf("%02X ",opcodeByteOne);
    
    unsigned char opcodeByteTwo;
    opcodeByteTwo=data[21];
    printf("%02X\n",opcodeByteTwo);

    // ARP Part - Sender MAC Address (Bytes 22 to 27)
    for(index=22;index<28;index++)
    {
        unsigned char currentByte;
        currentByte=data[index];
        printf("%02X ",currentByte);
    }
    printf("\n");

    // ARP Part - Sender IP Address (Bytes 28 to 31)
    for(index=28;index<32;index++)
    {
        unsigned char currentByte;
        currentByte=data[index];
        printf("%d",currentByte);
        
        if(index!=31)
            printf(".");
    }
    printf("\n");

    // ARP Part - Target MAC Address (Bytes 32 to 37)
    for(index=32;index<38;index++)
    {
        unsigned char currentByte;
        currentByte=data[index];
        printf("%02X ",currentByte);
    }
    printf("\n");

    // ARP Part - Target IP Address (Bytes 38 to 41)
    for(index=38;index<42;index++)
    {
        unsigned char currentByte;
        currentByte=data[index];
        printf("%d",currentByte);
        
        if(index!=41)
            printf(".");
    }
    printf("\n");
}