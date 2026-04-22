#include<stdio.h>
#include<fcntl.h>
#include<signal.h>
#include<unistd.h>
#include<string.h>
#include<stdlib.h>
#include<ctype.h>
#include"icmpRead.h"
#include"hexdump.h"
#include"arpRead.h"
#include"SynFlood.h"
#include"Realtimepacket.h"
#include"dumpingfunc.h"

int main(int argc,char *arg[])
{
    int numberOfArguments;
    numberOfArguments=argc;

    if(numberOfArguments==1)
        pipeline();

    else if(numberOfArguments==2)
    {
        int checkResultForL;
        checkResultForL=strcmp(arg[1],"-L");

        if(checkResultForL==0)
        {
            int selectedProtocolNumber;
            
            printf("Enter the Protocol No:\n");
            printf("1.TCP\n");
            printf("2.ICMP\n");
            printf("3.UDP\n");
            
            scanf("%d",&selectedProtocolNumber);
            
            char *liveMode;
            liveMode="live";
            
            Realtimepacket(liveMode,selectedProtocolNumber);
        }
        else
            printf("Wrong Format!!!\n");
    }

    else if(numberOfArguments==3)
    {
        int checkResultForS;
        checkResultForS=strcmp(arg[1],"-S");

        if(checkResultForS==0)
        {
            char *targetIP;
            targetIP=arg[2];
            
            SynFlood(targetIP);
            
            printf("\n\n\n\n");
            
            int sleepTime;
            sleepTime=1;
            sleep(sleepTime);
            
            commandLine(arg);
        }
        else
        {
            int checkResultForF;
            checkResultForF=strcmp(arg[1],"-F");

            if(checkResultForF==0)
            {
                int allProtocolChoice;
                allProtocolChoice=0;
                
                char *fileName;
                fileName=arg[2];
                
                Realtimepacket(fileName,allProtocolChoice);
            }
            else
            {
                printf("\n\n\n\n");
                
                int sleepTimeAgain;
                sleepTimeAgain=1;
                sleep(sleepTimeAgain);
                
                commandLine(arg);
            }
        }
    }
    return 0;
}
