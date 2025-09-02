#include <stdio.h>
#include <unistd.h>

int main() {
    
    char *args[2];
    args[0] = "/bin/bash";
    args[1] =  NULL;
    printf("Hello from test\n");
    execve(args[0], args, NULL);

    return 1;
}