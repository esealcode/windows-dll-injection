#define _WIN32_WINNT_WIN10 0x0A00
#include <windows.h>
#include <Psapi.h>
#include <stdio.h>
#pragma comment(lib, "psapi")

#define _SPAWN_CREATE_      1
#define _SPAWN_ATTACH_      2
#define _SPAWN_HIDED_       4
#define _SPAWN_FOR_DEBUG_   8

typedef struct _LSA_UNICODE_STRING {
  USHORT Length;
  USHORT MaximumLength;
  PWSTR  Buffer;
} LSA_UNICODE_STRING, *PLSA_UNICODE_STRING, UNICODE_STRING, *PUNICODE_STRING;

typedef struct __bytecode__ {
    ULONG restore_eip;
    struct bytecode {
        char* address;
        int   size;
    } bytecode;

    struct Ntdll {
        UNICODE_STRING* ntdll_unicode;
        char* bufAddr;
        int LdrLoadDll_RVA;
    } Ntdll;

    struct Dll {
        UNICODE_STRING* dll_unicode;
        char* bufAddr;
    } Dll;
} __bytecode__;

typedef struct spawnQuery {
    char                    flags;              // Flags such hide bit/spawning mode bit
    UNICODE_STRING          DllPath;            // Full DLL Path used to call LdrLoadDll with right DLL to spawn
    char*                   ExeName;            // Executable name to run if -c argument was used
    int                     pid;                // PID of active process to attach if -a argument was used
    HANDLE                  hProcess;
    HANDLE                  hThread;
} spawnQuery;

int (*DebugActiveProcessStop)(
  DWORD dwProcessId
);

/* 
    A simple module to patch some binary data into memory. Search binary pattern must have the same length as the replace binary data.
    @parameters
                char* memory : memory pointer to read/write at
                int   m_size : Size of the memory
                int   d_size : Size of search binary pattern/replace binary data
                char* s      : pointer to the search binary pattern
                char* r      : pointer to the replace binary data
    
    @return (void)
*/
int patch(char* memory, int m_size, int d_size, char* s, char* r) {
    register int i, y;
    char* ptr = memory;
    for ( ptr; ptr < memory + m_size; ptr++ ) {
        for ( y=0; y < d_size; y++ )
            if ( ptr[y] != s[y] ) {
                y=0; 
                break;
            }
        
        if ( y > 0 ) {
            for ( y=0; y < d_size; y++ )
                ptr[y] = r[y];
            return 1;
        }
    }

    return -1;
}

/*
    A simple module which output a common hexadecimal memory display
    @parameters
                char* memory : memory pointer to read at
                int   size   : size of the memory
                int   length : maximum size in bytes of one line, if NULL then 16 is chosen
                int   chunk  : size in bytes of chunk of binary data, if NULL then 4 is chosen
    
    @output Common hexadecimal memory view
    @return (void)
*/                                                                                                                                                                                                                          
void memory_view(unsigned char* memory, int m_size, int Llength, int chunk) {
    printf("Reading memory from 0x%x on %d bytes.\n", memory, m_size);
    if ( Llength == 0 )
        Llength = 16;
    
    if ( chunk == 0 )
        chunk = 4;

    register int i;

    for ( i=0; i < m_size; i++ ) {
        if ( !(i % chunk) )
            printf("  ");
        
        if ( !(i % Llength) )
            printf("\n0x%08x    ", (int) i);
        
        printf("%02x ", memory[i]);
    }
    printf("\n");
}

/*
    Transform 16 bits encoded string into truncated 8 bits encoded string.
*/
void unicode_to_ansi(char* unicode_string, int unicode_length) {
    char ansi[unicode_length];
    register int i, y;
    for ( i=0, y=0; i < unicode_length; i += 2, y++ ) {
        ansi[y] = (short)*(unicode_string + i) & 0xFF;
    }
    memset(unicode_string, 0x00, unicode_length);
    memcpy(unicode_string, ansi, unicode_length / 2);
}

/*
    Transform 8 bits encoded string into UNICODE string
*/
int ansi_to_unicode(WCHAR** unicode_ptr, char* ansi_string) {
    int ansi_len = strlen(ansi_string) + 1; // Get NULL byte len
    *unicode_ptr = (WCHAR *) calloc (1, ansi_len * 2); // Alloc null byte filled memory 

    register int i;
    for ( i=0; i < ansi_len; i++ )
        * ((short *) *unicode_ptr + i) = ansi_string[i];
    
    return ansi_len * 2;
}

/*
    Little module to free multiple memory zone with one function
    @noreturn
*/
void free_memory(int memory_area_count, ...) {
    va_list args;
    va_start(args, memory_area_count);
    
    for ( memory_area_count; memory_area_count > 0; memory_area_count-- )
        free(va_arg(args, char*));
}


int get_ntdll_function_rva(char* f_name) {

    char* Ntdll = (char *) GetModuleHandle("ntdll.dll");
    if ( Ntdll == NULL ) {
        printf("Unable to GetModuleHandle() on Ntdll. Code: %d\n", GetLastError());
        return 0;
    }

    char* f_addr = (char *) GetProcAddress( (HANDLE) Ntdll, f_name);
    if ( f_addr == NULL ) {
        printf("Unable to GetProcAddress() in Ntdll for function %s. Code: %d\n", f_name, GetLastError());
        return 0;
    }

    return f_addr - Ntdll;
}

void print_unicode(char* unicode, int length) {
    int i;
    for ( i=0; i < length; i++ )
        printf("%c", unicode[i], unicode[i]);
}

void usage( void ) {
    printf("Usage: SpawnDll -c <exe_file> <Dll_path> <flags> [--hide, --debug] (Create process, spawn DLL and run it)\n\tSpawnDll -a <pid> <Dll_path> <flags> [--hide, --debug] (Attach an active process, spawn DLL and continue it)\n");
}

int isOnlyDigits(char* str) {
    while ( *str )
        if ( !isdigit(*str++) )
            return 0;

    return 1; 
}

int get_parameters(int argc, char* argv[], spawnQuery* qSpawn) {
    printf("argv[0]: %s\nargv[1]: %s\n", argv[0], argv[1]);
    if ( argc < 2 ) {
        usage();
        return 0;
    }

    if ( strcmp(argv[1], "-c") == 0 ) {
        if ( argc < 4 ) {
            usage();
            return 0;
        }

        qSpawn->flags |= _SPAWN_CREATE_;
        qSpawn->ExeName = argv[2];
        qSpawn->DllPath.MaximumLength = ansi_to_unicode(&qSpawn->DllPath.Buffer, argv[3]);
        qSpawn->DllPath.Length = qSpawn->DllPath.MaximumLength - 2;
        
        while ( argc > 4 ) { // Some flags are requested
            if ( strcmp(argv[ argc - 1 ], "--hide") == 0 )
                qSpawn->flags |= _SPAWN_HIDED_;
            else if ( strcmp(argv[ argc - 1 ], "--debug") == 0 )
                qSpawn->flags |= _SPAWN_FOR_DEBUG_;
            argc--;
        }
    }
    else if ( strcmp(argv[1], "-a") == 0 ) {    
        if ( argc < 4 || !isOnlyDigits( argv[2] ) ) {
            usage();
            return 0;
        }

        qSpawn->flags |= _SPAWN_ATTACH_;
        qSpawn->pid = atoi( argv[2] );
        qSpawn->DllPath.MaximumLength = ansi_to_unicode(&qSpawn->DllPath.Buffer, argv[3]);
        qSpawn->DllPath.Length = qSpawn->DllPath.MaximumLength - 2;

        while ( argc > 4 ) { // Some flags are requested
            if ( strcmp(argv[argc-1], "--hide") == 0 )
                qSpawn->flags |= _SPAWN_HIDED_;
            else if ( strcmp(argv[argc-1], "--debug") == 0 ) 
                qSpawn->flags |= _SPAWN_FOR_DEBUG_;
            argc--;
        }
    }
    else {
        usage();
        return 0;
    }

    return 1;
}

int GetProcess(spawnQuery* qSpawn) {
    if ( qSpawn->flags & _SPAWN_CREATE_ ) {
        // Create process to get Process handle / Thread handle
        STARTUPINFOA SI;
        PROCESS_INFORMATION child_process;

        memset(&SI, 0x00, sizeof(STARTUPINFOA));
        memset(&child_process, 0x00, sizeof(PROCESS_INFORMATION));

        if ( CreateProcess(qSpawn->ExeName, NULL, NULL, NULL, FALSE, CREATE_SUSPENDED | DETACHED_PROCESS, NULL, NULL, &SI, &child_process) < 1 ) {
            printf("Unable to CreateProcess(). Code: %d\n", GetLastError());
            return 0;
        }

        qSpawn->hProcess = child_process.hProcess;
        qSpawn->hThread  = child_process.hThread;
        qSpawn->pid = child_process.dwProcessId;
    }
    else if ( qSpawn->flags & _SPAWN_ATTACH_ ) {
        // Debug active process by attaching to get Process handle / Thread handle   
        DEBUG_EVENT dbgEvnt;
        memset(&dbgEvnt, 0x00, sizeof(DEBUG_EVENT));

        if ( DebugActiveProcess(qSpawn->pid) == 0 ) {
            printf("Unable to DebugActiveProcess() on %d. Code: %d\n", qSpawn->pid, GetLastError());
            return 0;
        }
        
        WaitForDebugEvent(&dbgEvnt, INFINITE);
        while ( dbgEvnt.dwDebugEventCode != CREATE_PROCESS_DEBUG_EVENT ) {
            ContinueDebugEvent(dbgEvnt.dwProcessId, dbgEvnt.dwThreadId, DBG_CONTINUE);
            WaitForDebugEvent(&dbgEvnt, INFINITE);
        }

        // Process is fully suspended rn
        qSpawn->hProcess = dbgEvnt.u.CreateProcessInfo.hProcess;
        qSpawn->hThread  = dbgEvnt.u.CreateProcessInfo.hThread;
    }

    return 1;
}

int SpawnDll(spawnQuery* qSpawn) {

    char spawnDll[] = "\x90\x90\x60\x55\x89\xE5\x83\xEC\x20\xBF\xEE\xEE\xEE\xBE\xC7\x04\x24\x00\x11\x00\x11\xE8\x40\x00\x00\x00\x83\xF8\x00\x74\x31\x8B\x70\x18\x01\xFE\xC7\x44\x24\x10\xEA\xEE\xEE\xBE\x8D\x5C\x24\xE0\xC7\x04\x24\x00\x00\x00\x00\xC7\x44\x24\x04\x00\x00\x00\x00\x8B\x54\x24\x10\x89\x54\x24\x08\x89\x5C\x24\x0C\xFF\xD6\x83\xEC\x10\x89\xEC\x5D\x61\x68\xEA\xBE\xEA\xBE\xC3\x57\x53\x55\x89\xE5\x83\xEC\x10\x64\x8B\x3D\x30\x00\x00\x00\x8B\x7F\x0C\x85\xFF\x74\x32\x8D\x7F\x0C\x89\x7C\x24\x0C\x8B\x3F\x85\xFF\x74\x25\x8D\x5F\x2C\x89\x1C\x24\x8B\x5D\x10\x89\x5C\x24\x04\xE8\x1E\x00\x00\x00\x83\xF8\x01\x74\x0A\x8B\x3F\x39\x7C\x24\x0C\x74\x06\xEB\xDF\x89\xF8\xEB\x05\xB8\x00\x00\x00\x00\x89\xEC\x5D\x5B\x5F\xC3\x51\x57\x56\x55\x89\xE5\x8B\x75\x14\x8B\x7D\x18\x66\xA7\x75\x1B\x66\x8B\x4E\xFE\x81\xE1\xFF\xFF\x00\x00\x8B\x7F\x02\x8B\x76\x02\xF3\xA6\x75\x07\xB8\x01\x00\x00\x00\xEB\x07\xB8\x00\x00\x00\x00\xEB\x00\x89\xEC\x5D\x5E\x5F\x59\xC3";

    char spawnHideDll[] = "\x90\x90\x60\x55\x89\xE5\x83\xEC\x20\xBF\xEE\xEE\xEE\xBE\xC7\x04\x24\x00\x11\x00\x11\xE8\x92\x00\x00\x00\x83\xF8\x00\x74\x42\x8B\x70\x18\x01\xFE\xC7\x44\x24\x10\xEA\xEE\xEE\xBE\x8D\x5C\x24\xE0\xC7\x04\x24\x00\x00\x00\x00\xC7\x44\x24\x04\x00\x00\x00\x00\x8B\x54\x24\x10\x89\x54\x24\x08\x89\x5C\x24\x0C\xFF\xD6\x83\xEC\x10\x8B\x54\x24\x10\x89\x14\x24\xE8\x0F\x00\x00\x00\x83\xF8\x00\x74\x00\x89\xEC\x5D\x61\x68\xEA\xBE\xEA\xBE\xC3\x56\x53\x52\x55\x89\xE5\x83\xEC\x10\x8B\x74\x24\x14\x89\x34\x24\xE8\x2C\x00\x00\x00\x83\xF8\x00\x74\x1B\x8D\x50\x18\x8B\x30\x8B\x58\x04\x89\x33\x89\x5E\x04\x83\xC0\x08\x39\xD0\x75\xEF\xB8\x01\x00\x00\x00\xEB\x05\xB8\x00\x00\x00\x00\x89\xEC\x5D\x5A\x5B\x5E\xC3\x57\x53\x55\x89\xE5\x83\xEC\x10\x64\x8B\x3D\x30\x00\x00\x00\x8B\x7F\x0C\x85\xFF\x74\x32\x8D\x7F\x0C\x89\x7C\x24\x0C\x8B\x3F\x85\xFF\x74\x25\x8D\x5F\x2C\x89\x1C\x24\x8B\x5D\x10\x89\x5C\x24\x04\xE8\x1E\x00\x00\x00\x83\xF8\x01\x74\x0A\x8B\x3F\x39\x7C\x24\x0C\x74\x06\xEB\xDF\x89\xF8\xEB\x05\xB8\x00\x00\x00\x00\x89\xEC\x5D\x5B\x5F\xC3\x51\x57\x56\x55\x89\xE5\x8B\x75\x14\x8B\x7D\x18\x66\xA7\x75\x1B\x66\x8B\x4E\xFE\x81\xE1\xFF\xFF\x00\x00\x8B\x7F\x02\x8B\x76\x02\xF3\xA6\x75\x07\xB8\x01\x00\x00\x00\xEB\x07\xB8\x00\x00\x00\x00\xEB\x00\x89\xEC\x5D\x5E\x5F\x59\xC3";

    if ( qSpawn->flags & _SPAWN_FOR_DEBUG_ ) { 
        // Put INT3 instruction for debugging
        spawnDll[0] = 0xcc;
        spawnHideDll[0] = 0xcc; 
    }

    char* spawnBytecode;

    CONTEXT pCtx;
    __bytecode__ bytecode;
    HANDLE allocPage;

    SIZE_T writed_bytes;

    // Get main thread context for the process
    pCtx.ContextFlags = CONTEXT_FULL;
    if ( GetThreadContext(qSpawn->hThread, &pCtx) == 0 ) {
        printf("Unable to GetThreadContext(). Code: %d\n", GetLastError());
        return 0;
    }

    bytecode.restore_eip = pCtx.Eip;

    printf("Child EIP: 0x%x\n", pCtx.Eip);
    printf("Child PID: %d\n", qSpawn->pid);

    allocPage = VirtualAllocEx(qSpawn->hProcess, NULL, 4096, MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE);
    if ( allocPage == NULL ) {
        printf("Unable to allocate child memory page. Code: %d\n", GetLastError());
        return 0;
    }
    printf("Allocated page at 0x%x on child address space\n", allocPage);

    bytecode.bytecode.address = allocPage;  
    // Adjust bytecode pointer
    if ( qSpawn->flags & _SPAWN_HIDED_ ) {
        spawnBytecode = spawnHideDll;
        bytecode.bytecode.size = sizeof(spawnHideDll);
    }
    else {
        spawnBytecode = spawnDll;
        bytecode.bytecode.size = sizeof(spawnDll);
    }

    bytecode.Ntdll.ntdll_unicode = (UNICODE_STRING *) (bytecode.bytecode.address + bytecode.bytecode.size + 128); // Store structure in safe zone
    bytecode.Ntdll.bufAddr = allocPage + 2048;
    bytecode.Ntdll.LdrLoadDll_RVA = get_ntdll_function_rva("LdrLoadDll");

    bytecode.Dll.dll_unicode = (UNICODE_STRING *) (bytecode.bytecode.address + bytecode.bytecode.size + 256); // Store structure in safe zone 
    bytecode.Dll.bufAddr = allocPage + 2176;

    // Initialize UNICODE structure which will be writed in child process allocated memory
    WCHAR NtdllName[] = L"ntdll.dll";
    UNICODE_STRING uNtdll;
    uNtdll.Length = sizeof(NtdllName) - 2; // Exclude Unicode NULL byte
    uNtdll.MaximumLength = sizeof(NtdllName);
    uNtdll.Buffer = (PWSTR) bytecode.Ntdll.bufAddr;

    UNICODE_STRING uDll;
    uDll.Length = qSpawn->DllPath.Length; // Exclude Unicode NULL byte
    uDll.MaximumLength = qSpawn->DllPath.MaximumLength;
    uDll.Buffer = (PWSTR) bytecode.Dll.bufAddr;

    printf("__bytecode__ structure:\n\tBytecode start address at 0x%x\n\tBytecode size: %d\n\tNtdll UNICODE structure at 0x%x\n\tNtdll buffer address at 0x%x\n\tNtdll LdrLoadDll RVA: 0x%x\n\tDll UNICODE structure at 0x%x\n\tDll buffer address at 0x%x\n\n", 
            bytecode.bytecode.address,
            bytecode.bytecode.size,
            bytecode.Ntdll.ntdll_unicode,
            bytecode.Ntdll.bufAddr,
            bytecode.Ntdll.LdrLoadDll_RVA,
            bytecode.Dll.dll_unicode,
            bytecode.Dll.bufAddr);


    // Write UNICODE_STRING structures
    if ( WriteProcessMemory(qSpawn->hProcess, bytecode.Ntdll.ntdll_unicode, &uNtdll, sizeof(UNICODE_STRING), &writed_bytes) < 1 ) {
        printf("Unable to write ntdll_unicode UNICODE_STRING structure in child memory. Code: %d\n", GetLastError());
        return 0;
    }

    if ( WriteProcessMemory(qSpawn->hProcess, bytecode.Dll.dll_unicode, &uDll, sizeof(UNICODE_STRING), &writed_bytes) < 1 ) {
        printf("Unable to write dll_unicode UNICODE_STRING structure in child memory. Code: %d\n", GetLastError());
        return 0;
    }

    // Write UNICODE_STRING buffers
    if ( WriteProcessMemory(qSpawn->hProcess, bytecode.Ntdll.bufAddr, NtdllName, uNtdll.Length, &writed_bytes) < 1 ) {
        printf("Unable to write Ntdll UNICODE_STRING buffer in child memory. Code: %d\n", GetLastError());
        return 0;
    }

    if ( WriteProcessMemory(qSpawn->hProcess, bytecode.Dll.bufAddr, qSpawn->DllPath.Buffer, uDll.MaximumLength, &writed_bytes) < 1 ) {
        printf("Unable to write Dll UNICODE_STRING buffer in child memory. Code: %d\n", GetLastError());
        return 0;
    }

    // Patch Bytecode
    if ( patch(spawnBytecode, bytecode.bytecode.size, sizeof(DWORD), "\xee\xee\xee\xbe", (char *) &bytecode.Ntdll.LdrLoadDll_RVA) == -1 )
        printf("Unable to patch bytecode with LdrLoadDll RVA.\n");
    
    if ( patch(spawnBytecode, bytecode.bytecode.size, sizeof(DWORD), "\x00\x11\x00\x11", (char *) &bytecode.Ntdll.ntdll_unicode) == -1 )
        printf("Unable to patch bytecode with Ntdll UNICODE_STRING pointer.\n");
    
    if ( patch(spawnBytecode, bytecode.bytecode.size, sizeof(DWORD), "\xea\xee\xee\xbe", (char *) &bytecode.Dll.dll_unicode) == -1 )
        printf("Unable to patch bytecode with Dll UNICODE_STRING pointer.\n");

    if ( patch(spawnBytecode, bytecode.bytecode.size, sizeof(DWORD), "\xea\xbe\xea\xbe", (char *) &bytecode.restore_eip) == -1 )
        printf("Unable to patch bytecode with RtlUserThreadStart EIP.\n");

    printf("spawnBytecode bytecode memory:\n");
    memory_view(spawnBytecode, bytecode.bytecode.size, 0, 0);

    if ( WriteProcessMemory(qSpawn->hProcess, bytecode.bytecode.address, spawnBytecode, bytecode.bytecode.size, &writed_bytes) < 1 ) {
        printf("Unable to write spawnBytecode routine in child memory. Code: %d\n", GetLastError());
        return 0;
    }

    pCtx.Eip = (DWORD) bytecode.bytecode.address; // Jump on our bytecode
    if ( SetThreadContext(qSpawn->hThread, &pCtx) == 0 ) {
        printf("Unable to SetThreadContext(). Code: %d\n", GetLastError());
        return 0;
    }

    printf("R/Enter to release child...\n");

    int chr;
    while ( chr != 'R' ) {
        GetThreadContext(qSpawn->hThread, &pCtx);
        printf("EIP at 0x%x\n", pCtx.Eip);
        chr = getchar();
    }

    if ( qSpawn->flags & _SPAWN_CREATE_ )
        ResumeThread(qSpawn->hThread);
    else if ( qSpawn->flags & _SPAWN_ATTACH_ ) 
        if ( DebugActiveProcessStop(qSpawn->pid)  == 0 ) {
            printf("Unable to release attached process. Code: %d\n", GetLastError());
            return 0;
        }

    return 1;
}

int main ( int argc, char* argv[] ) {
    HMODULE Kernel32 = GetModuleHandle("Kernel32.dll");
    DebugActiveProcessStop = (char *) GetProcAddress(Kernel32, "DebugActiveProcessStop");
    printf("DebugActiveProcessStop address at 0x%x\n", DebugActiveProcessStop);

    spawnQuery qSpawn;
    memset(&qSpawn, 0x00, sizeof(spawnQuery));
    if ( !get_parameters(argc, argv, &qSpawn) )
        return 0;

    printf("Spawn structure:\n\tFlags: 0x%x\n\tUNICODE DllPath:\n\t\tMaximumLength: %d\n\t\tLength: %d\n\t\tBuffer: 0x%x\n\tExeName: %s\n\tpid: %d\n\thProcess: 0x%x\n\thThread: 0x%x\n\n", qSpawn.flags, qSpawn.DllPath.MaximumLength, qSpawn.DllPath.Length, qSpawn.DllPath.Buffer, qSpawn.ExeName, qSpawn.pid, qSpawn.hProcess, qSpawn.hThread);
    memory_view(qSpawn.DllPath.Buffer, qSpawn.DllPath.MaximumLength, 0, 0);
    print_unicode(qSpawn.DllPath.Buffer, qSpawn.DllPath.MaximumLength);

    if ( GetProcess  (&qSpawn) == 0 ) {
        printf("Unable to GetProcess().\n");
        return 0;
    }
    getchar();
    if ( SpawnDll    (&qSpawn) == 0 ) {
        printf("Unable to SpawnDll().\n");
        TerminateProcess(qSpawn.hProcess,  0);
        return 0;
    }

    /*
    typedef struct _PEB {
        BYTE                          Reserved1[2];             0x00
        BYTE                          BeingDebugged;            0x02
        BYTE                          Reserved2[1];             0x03
        PVOID                         Reserved3[2];             0x04
        PPEB_LDR_DATA                 Ldr;                      0x0c
        PRTL_USER_PROCESS_PARAMETERS  ProcessParameters;        0x10
        BYTE                          Reserved4[104];           0x14
        PVOID                         Reserved5[52];            0x80
        PPS_POST_PROCESS_INIT_ROUTINE PostProcessInitRoutine;   0x14c
        BYTE                          Reserved6[128];           0x150
        PVOID                         Reserved7[1];             0x1d0
        ULONG                         SessionId;                0x1d4
    } PEB, *PPEB;

    typedef struct _PEB_LDR_DATA {
        DWORD dwLength;                                         0x00
        DWORD dwInitialized;                                    0x04
        LPVOID lpSsHandle;                                      0x08
        LIST_ENTRY InLoadOrderModuleList;                       0x0c
            LIST_ENTRY *Flink                                   0x0c
            LIST_ENTRY *Blink                                   0x10
        LIST_ENTRY InMemoryOrderModuleList;                     0x14
            LIST_ENTRY *Flink                                   0x14
            LIST_ENTRY *Blink                                   0x18
        LIST_ENTRY InInitializationOrderModuleList;             0x1c
            LIST_ENTRY *Flink                                   0x1c
            LIST_ENTRY *Blink                                   0x20
        LPVOID lpEntryInProgress;                               0x24
    } PEB_LDR_DATA, *PPEB_LDR_DATA;

    typedef struct _LIST_ENTRY {
        struct _LIST_ENTRY *Flink;                              0x00
        struct _LIST_ENTRY *Blink;                              0x04
    } LIST_ENTRY, *PLIST_ENTRY, *RESTRICTED_POINTER PRLIST_ENTRY;

    typedef struct _LDR_DATA_TABLE_ENTRY {
     LIST_ENTRY InLoadOrderLinks;                               0x00
            LIST_ENTRY *Flink                                   0x00
            LIST_ENTRY *Blink                                   0x04
     LIST_ENTRY InMemoryOrderLinks;                             0x08
            LIST_ENTRY *Flink                                   0x08
            LIST_ENTRY *Blink                                   0x0c
     LIST_ENTRY InInitializationOrderLinks;                     0x10
            LIST_ENTRY *Flink                                   0x10
            LIST_ENTRY *Blink                                   0x14
     PVOID DllBase;                                             0x18
     PVOID EntryPoint;                                          0x1c
     ULONG SizeOfImage;                                         0x20
     UNICODE_STRING FullDllName;                                0x24
            USHORT Length                                       0x24
            USHORT MaximumLength                                0x26
            PWSTR  Buffer                                       0x28
     UNICODE_STRING BaseDllName;                                0x2c
            USHORT Length                                       0x2c
            USHORT MaximumLength                                0x2e
            PWSTR  Buffer                                       0x30
     ULONG Flags;                                               0x34
     WORD LoadCount;                                            0x38
     WORD TlsIndex;                                             0x3a
     LIST_ENTRY HashLinks;                                      0x3c
            LIST_ENTRY *Flink                                   0x3c
            LIST_ENTRY *Blink                                   0x40
     PVOID SectionPointer;                                      0x3c
     ULONG CheckSum;                                            0x40
     ULONG TimeDateStamp;                                       0x44
     PVOID LoadedImports;                                       0x44
     _ACTIVATION_CONTEXT * EntryPointActivationContext;         0x48
     PVOID PatchInformation;                                    0x4c
    } LDR_DATA_TABLE_ENTRY, *PLDR_DATA_TABLE_ENTRY;

    */

    printf("K/Enter to terminate child...\n");

    int chr;
    while ( chr != 'K' )
        chr = getchar();

    TerminateProcess(qSpawn.hProcess,  0);
    return 0;
}