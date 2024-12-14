.code

extern g_bytepatch_addr:qword

ObpReferenceObjectByHandleWithTagHookTrampoline proc
    mov     [rsp+20h], r9b
	mov     [rsp+18h], r8
	mov     [rsp+10h], edx
	mov     rax, [g_bytepatch_addr]
	add     rax, 0eh
	jmp     rax
ObpReferenceObjectByHandleWithTagHookTrampoline endp

end