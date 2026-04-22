#include<stdio.h>
#include<stdlib.h>
#include<string.h>
#include<netinet/ip.h>
#include<sys/socket.h>
#include<arpa/inet.h>
#include<sys/types.h>
#include<unistd.h>
#include"PacketHeader.h"
#include"SynFlood.h"

#define MAX 100000

FILE *filepointer;
char fileName[100];
int pacekt_no;
long int fake_ip[MAX],tcp=0,http=0,ssl=0;
long int false_no=-1,fake_num=-1;
struct Synfld spam[MAX];

int is_same(int address1[],uint32_t address2[])
{
    int i;
    for(i=0;i<4;i++)
    {
        int val1;
        val1=address1[i];
        
        uint32_t val2;
        val2=address2[i];
        
        if(val1!=val2)
            return 0;
    }
    return 1;
}

void checking_syn(int address[],int s_a)
{
    long int syn_val;
    long int flag;
    flag=0;
    
    int same;
    same=0;
    
    long int i;
    long int ind;
    ind=0;
    
    for(i=0;i<=false_no;i++)
    {
        same=is_same(address,spam[i].IP);
        
        if(same!=0)
        {
            ind=i;
            break;
        }
    }
    
    if(same==1)
    {
        flag=1;
        
        if(s_a==1)
        {
            syn_val=spam[ind].syn;
            syn_val++;
            spam[ind].syn=syn_val;
        }
        else
        {
            syn_val=spam[ind].syn_ack;
            syn_val++;
            spam[ind].syn_ack=syn_val;
        }
    }

    if(flag==0)
    {
        false_no++;
        
        int j;
        for(j=0;j<4;j++)
        {
            int currentIpVal;
            currentIpVal=address[j];
            spam[false_no].IP[j]=currentIpVal;
        }
        
        if(s_a==1)
            spam[false_no].syn=1;
        else
            spam[false_no].syn_ack=1;
    }
}

int SynFlood(char *pcapfile)
{
    struct globalhdr Global;
    char temp[20];
    strcpy(temp,"IP Source Address");
    
    strcpy(fileName,pcapfile);
    filepointer=fopen(fileName,"rb");
    
    if(filepointer==NULL)
    {
        printf("Error opening file.\n");
        return -1;
    }

    int elementSize;
    elementSize=sizeof(struct globalhdr);
    fread(&Global,elementSize,1,filepointer);
    
    printf("Analysing packets\n\n");
    printf("%-20s","Packet No");
    printf("%-20s\n",temp);
    
    // Packet analysis loop goes here...
    
    printf("Syn-Flood Detected.\n");
    
    fclose(filepointer);
    return 0;
}
