#include<stdio.h>
#include<unistd.h>
#include<string.h>
#include<stdlib.h>
#include<ctype.h>
#include"icmpRead.h"
#include"hexdump.h"
#include"arpRead.h"
#include"SynFlood.h"
#include"Realtimepacket.h"

void pipeline();
void commandLine(char *pcapfile[100]);

void pipeline()
{
    unsigned int value;
    value=0;
    
    unsigned char data[2000];
    int i;
    int packetlen;
    
    // Global Header reading (First 24 bytes of a PCAP file)
    for(i=0;i<24;i++)
    {
        value=getchar();
        
        if(value==EOF)
            return;
            
        unsigned int maskedValue;
        maskedValue=value&0xFF;
        
        data[i]=maskedValue;
    }
    data[i]='\0';
    
    // Record loop (Reading packet by packet)
    while(1)
    {
        // Record Header reading (16 bytes before every packet)
        for(i=0;i<16;i++)
        {
            value=getchar();
            
            if(value==EOF)
                return;
                
            unsigned int maskedValue;
            maskedValue=value&0xFF;
            
            data[i]=maskedValue;
        }
        data[i]='\0';
        
        // Getting packet length from the 8th byte of the record header
        unsigned char lengthByte;
        lengthByte=data[8];
        packetlen=lengthByte;
        
        // Packet data reading (Actual captured data)
        for(i=0;i<packetlen;i++)
        {
            value=getchar();
            
            if(value==EOF)
                return;
                
            unsigned int maskedValue;
            maskedValue=value&0xFF;
            
            data[i]=maskedValue;
        }
        data[i]='\0';
        
        packetinfo(data,packetlen);
    }
}

void commandLine(char *pcapfile[100])
{
    FILE *fp;
    char *fileName;
    fileName=pcapfile[2];
    
    fp=fopen(fileName,"rb");
    
    if(fp==NULL)
    {
        printf("No such pcap file found. Error.\n");
        exit(1);
    }
    
    unsigned char data[2000];
    unsigned int value;
    int i;
    int packetlen;
    
    // Global Header reading from file
    for(i=0;i<24;i++)
    {
        value=fgetc(fp);
        
        if(value==EOF)
            return;
            
        unsigned int maskedValue;
        maskedValue=value&0xFF;
        
        data[i]=maskedValue;
    }
    data[i]='\0';
    
    while(1)
    {
        // Pcap Record Header from file
        for(i=0;i<16;i++)
        {
            value=fgetc(fp);
            
            if(value==EOF)
                return;
                
            unsigned int maskedValue;
            maskedValue=value&0xFF;
            
            data[i]=maskedValue;
        }
        data[i]='\0';
        
        unsigned char lengthByte;
        lengthByte=data[8];
        packetlen=lengthByte;
        
        // Packet data from file
        for(i=0;i<packetlen;i++)
        {
            value=fgetc(fp);
            
            if(value==EOF)
                break;
                
            unsigned int maskedValue;
            maskedValue=value&0xFF;
            
            data[i]=maskedValue;
        }
        data[i]='\0';
        
        char *flagArgument;
        flagArgument=pcapfile[1];
        
        int checkResultForA;
        checkResultForA=strcmp(flagArgument,"-A");
        
        if(checkResultForA==0)
        {
            packetinfo(data,packetlen);
        }
        else
        {
            int checkResultForI;
            checkResultForI=strcmp(flagArgument,"-I");
            
            if(checkResultForI==0)
            {
                ICMPinfo(data,packetlen);
            }
        }
        
        packetlen=0;
    }
    fclose(fp);
}