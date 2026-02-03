#include <unistd.h>
#include <stdio.h>

int main() 
{
    printf("Target started, pid=%d\n", getpid());
    fflush(stdout);
    while (1) sleep(1);
}
