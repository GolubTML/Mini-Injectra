#include <fcntl.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>
#include <stdio.h>

__attribute__((constructor))
void init() 
{
    write(2, "[Injectra] payload loaded\n", 26);

    FILE* file = fopen("/tmp/injectralog.txt", "w");
    fprintf(file, "Hello from log");

    fclose(file);
}
