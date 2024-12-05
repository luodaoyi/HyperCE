.code

extern g_bytepatch_addr:qword

ObReferenceObjectByHandleWithTagHookTrampoline proc
    sub     rsp, 48h
	mov    rax, [g_bytepatch_addr]
	add    rax, 0ch
	push    rax
	mov     rax, [rsp+80h]
	ret
ObReferenceObjectByHandleWithTagHookTrampoline endp

end