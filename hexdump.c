#include<stdio.h>
#include<ctype.h>
#include<string.h>

void GetHexDump(const void *data,size_t size,char *output)
{
    unsigned char *p;
    p=(unsigned char *)data;
    
    char hex_part[50],ascii_part[20];
    output[0]='\0';
    
    size_t i,j;
    
    for(i=0;i<size;i=i+16)
    {
        hex_part[0]='\0';
        ascii_part[0]='\0';

        for(j=0;j<16;j++)
        {
            size_t currentIndex;
            currentIndex=i+j;
            
            if(currentIndex<size)
            {
                unsigned char currentValue;
                currentValue=p[currentIndex];
                
                char tempForHex[4];
                sprintf(tempForHex,"%02X ",currentValue);
                strcat(hex_part,tempForHex);
                
                int printableCheck;
                printableCheck=isprint(currentValue);
                
                char tempForAscii[4];
                if(printableCheck!=0)
                    sprintf(tempForAscii,"%c",currentValue);
                else
                    sprintf(tempForAscii,".");
                    
                strcat(ascii_part,tempForAscii);
            }
            else
            {
                char emptySpace[4];
                sprintf(emptySpace,"   ");
                strcat(hex_part,emptySpace);
            }
        }
        
        char fullLine[100];
        sprintf(fullLine,"%s | %s\n",hex_part,ascii_part);
        strcat(output,fullLine);
        
        size_t currentOutputLength;
        currentOutputLength=strlen(output);
        
        if(currentOutputLength>800)
            break;
    }
}