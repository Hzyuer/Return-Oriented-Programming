#include<stdio.h>
#include<stdlib.h>
#include<unistd.h>
int dofunc(){
    char b[8] = {};
    write(1,"input:",6);
    read(0,b,0x200);
    //printf(b);
    write(1,"bye",3);
    return 0;
}

int main(){
    dofunc();
    return 0;
}