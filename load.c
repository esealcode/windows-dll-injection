#include <stdio.h>
#include <windows.h>

BOOL APIENTRY DllMain( HANDLE hModule, DWORD nReason, LPVOID lpReserved )
{
    if ( nReason == DLL_PROCESS_ATTACH ) {
        const char* buf = "Dll here !\n";
        FILE* fd = fopen("log.txt", "a");
        if ( fd == NULL )
            return (-1);

        fwrite(buf, sizeof(char), strlen(buf), fd);

        fclose(fd);
    }

    return 1;
}