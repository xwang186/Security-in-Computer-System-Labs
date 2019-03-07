#include <stdio.h>
unsigned char xyz[200] = {

};
int main()
{
int i;
for (i=0; i<200; i++){
printf("%x", xyz[i]);
}
printf("\n");
}