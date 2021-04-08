global _WinMain@16

section .text
	
	_WinMain@16:
		int3
		nop
		pushad ; Push context 
		push ebp
		mov  ebp, esp
		sub  esp, 0x20
		mov  edi, 0xbeeeeeee 			; RVA of LdrLoadDll will be patched here
		mov  dword [esp], 0x11001100 	; Patch ntdll.dll UNICODE_STRING pointer here
		call GetPebEntry
		cmp  eax, 0
		je   resumeMainThread
		mov  esi, dword [eax+0x18] ; Get module entry DllBase value
		add  esi, edi ; Add RVA to DllBase

		; esi now contain LdrLoadDll function pointer
		; NTSTATUS (WINAPI *LdrLoadDll)(IN PWCHAR PathToFile OPTIONAL,IN ULONG Flags OPTIONAL,IN PUNICODE_STRING ModuleFileName,OUT PHANDLE ModuleHandle);  
		mov  dword [esp+0x10], 0xbeeeeeea ; Store Dll UNICODE in stack
		lea  ebx, [esp-32]
		mov  dword [esp], 0 ; path
		mov  dword [esp+0x04], 0 ; flag
		mov  edx,  dword [esp+0x10]
		mov  dword [esp+0x08], edx ; UNICODE pointer
		mov  dword [esp+0x0c], ebx ; Handle beyond esp
		call esi
		sub  esp, 0x10 ; LdrLoadDll RETN 10 and fuck the ESP register, idk why :(

		resumeMainThread:
			mov esp, ebp ; Restore initial ESP
			pop ebp
			popad ; Pop context
			push 0xbeeabeea ; (eip) RtlUserThreadStart address patched here	
			ret

	; _LDR_PEB_DATA_ENTRY* GetPebEntry(UNICODE_STRING* module_name);
	GetPebEntry:
		push edi
		push ebx
		push ebp
		mov  ebp, esp ; Start new stack frame
		sub  esp, 0x10 ; Allocate 16 bytes for stack frame
		; UNICODE_STRING* module_name at [ebp+0x10]
		mov  edi, [fs:0x30] ; Move PEB pointer to edi
		mov  edi, dword [edi+0x0c] ; Move _LDR_PEB_DATA_ENTRY pointer to edi
		test edi, edi
		jz   GetPebEntryError
		lea  edi, [edi+0x0c]
		mov  [esp+0x0c], edi ; Stop InLoadOrderLinks address ( list will point back to it when it loop )
		mov  edi, dword [edi] ; Move InLoadOrderLinks Flink pointer, which point on the first module entry to edx
		test edi, edi
		jz   GetPebEntryError

		LoopPebEntry:
			lea  ebx, [edi+0x2c] ; Move module BaseName UNICODE_STRING pointer to ebx
			mov  dword [esp], ebx
			mov  ebx, dword [ebp+0x10] ; Move argument UNICODE_STRING pointer module name
			mov  dword [esp+0x04], ebx
			call UnicodeCmp
			cmp  eax, 1 ; Check for string equality
			je   LoopEntryFound

			LoopPebEntryContinue:
				mov  edi, [edi] ; Point to next module entry
				cmp  [esp+0x0c], edi ; Check if we jumped on InLoadOrderLinks, if so we finished to loop and we not matched module
				je   GetPebEntryError
				jmp  LoopPebEntry

			LoopEntryFound:
				mov  eax, edi ; Return module PEB entry address
				jmp  GetPebEntryReturn

		GetPebEntryError:
			mov  eax, 0 ; Return a NULL pointer
			;jmp  GetPebEntryReturn

		GetPebEntryReturn:
			mov  esp, ebp
			pop  ebp
			pop  ebx
			pop  edi
			ret
	
	; int UnicodeCmp(UNICODE_SRING* u1, UNICODE_STRING* u2);	
	UnicodeCmp:
		push ecx
		push edi
		push esi
		push ebp
		mov  ebp, esp
		; *u1 at [ebp+0x0c], *u2 at [ebp+0x08]
		mov  esi, [ebp+0x14] 
		mov  edi, [ebp+0x18]
		cmpsw ; Check if length of module names are same, if not then it's useless to continue
		jne  UnicodeCmpNotEqual
		mov  cx,  word [esi-2] ; Sub by 2 because cmpsw incremented by WORD size
		and  ecx, 0xFFFF		; Store only short size
		; Increment by two to pass MaximumLength WORD and jump to Buffer address
		mov  edi, [edi+2] 		; Store unicode string pointer
		mov  esi, [esi+2]		; Store unicode string pointer
		rep cmpsb ; Repetition, compare the module name to the searched module name
		jne  UnicodeCmpNotEqual
		mov  eax, 1
		jmp UnicodeCmpReturn

		UnicodeCmpNotEqual:
			mov eax, 0
			jmp UnicodeCmpReturn

		UnicodeCmpReturn:
			mov  esp, ebp
			pop  ebp
			pop  esi
			pop  edi
			pop  ecx
			ret