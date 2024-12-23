.code

extern g_NtQuerySystemInformation:qword

NtQuerySystemInformationHookTrampoline proc
    push    rbx
	sub     rsp, 30h
	xor     r10d, r10d
	mov     r11d, r8d
	mov     rax, [g_NtQuerySystemInformation]
	add     rax, 0ch
	jmp     rax
NtQuerySystemInformationHookTrampoline endp

end