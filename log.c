#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main ( void ) {
    __asm__("nop");
    FILE *fd = fopen("log.txt", "a");
    if ( fd == NULL ) {
        printf("Error opening log file.\n");
        return (-1);
    }

    const char* buf = "There is some log.\n";
    fwrite(buf, sizeof(char), strlen(buf), fd);

    fclose(fd);
    
    printf("Execution logged.\n");

    while ( 1 );

    return 0;
}