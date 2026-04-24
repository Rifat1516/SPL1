#include<stdio.h>
#include<stdlib.h>
#include<ctype.h>
#include"icmpRead.h"

void ICMPinfo(unsigned char *data,int size)
{
    int index;
    unsigned char typeArray[2];
    int typeIndex;
    for(index=0;index<6;index++)
    {
        unsigned char currentByte;
        currentByte=data[index];
        printf("%02X ",currentByte);
    }
    printf("\n");
    for(index=6;index<12;index++)
    {
        unsigned char currentByte;
        currentByte=data[index];
        printf("%02X ",currentByte);
    }
    printf("\n");
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
    unsigned char tosByte;
    tosByte=data[15];
    printf("%02X\n",tosByte);
    for(index=16;index<18;index++)
    {
        unsigned char currentByte;
        currentByte=data[index];
        printf("%02X ",currentByte);
    }
    printf("\n");
    for(index=18;index<20;index++)
    {
        unsigned char currentByte;
        currentByte=data[index];
        printf("%02X ",currentByte);
    }
    printf("\n");
    unsigned char flagsByte;
    flagsByte=data[20];
    printf("%d\n",flagsByte);
    unsigned char fragOffsetByte;
    fragOffsetByte=data[21];
    printf("%d\n",fragOffsetByte);
    unsigned char ttlByte;
    ttlByte=data[22];
    printf("%d\n",ttlByte);
    unsigned char protocolByte;
    protocolByte=data[23];
    
    if(protocolByte==1)
        printf("1\n");
    for(index=24;index<26;index++)
    {
        unsigned char currentByte;
        currentByte=data[index];
        printf("%02X ",currentByte);
    }
    printf("\n");
    for(index=26;index<30;index++)
    {
        unsigned char currentByte;
        currentByte=data[index];
        printf("%d",currentByte);
        
        if(index!=29)
            printf(".");
    }
    printf("\n");
    for(index=30;index<34;index++)
    {
        unsigned char currentByte;
        currentByte=data[index];
        printf("%d",currentByte);
        
        if(index!=33)
            printf(".");
    }
    printf("\n");

    unsigned char icmpType;
    icmpType=data[34];
    printf("%d\n",icmpType);

    unsigned char icmpCode;
    icmpCode=data[35];
    printf("%d\n",icmpCode);

    for(index=36;index<38;index++)
    {
        unsigned char currentByte;
        currentByte=data[index];
        printf("%02X ",currentByte);
    }
    printf("\n");

    for(index=38;index<40;index++)
    {
        unsigned char currentByte;
        currentByte=data[index];
        printf("%02X ",currentByte);
    }
    printf("\n");

    for(index=40;index<42;index++)
    {
        unsigned char currentByte;
        currentByte=data[index];
        printf("%02X ",currentByte);
    }
    printf("\n");

    for(index=42;index<50;index++)
    {
        unsigned char currentByte;
        currentByte=data[index];
        printf("%02X ",currentByte);
    }
    printf("\n");

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
