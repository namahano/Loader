.code
PUBLIC SysNtCreateSection
SysNtCreateSection PROC
    mov r10, rcx
    mov eax, 4Ah
    syscall
    ret
SysNtCreateSection ENDP
END