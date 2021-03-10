.code
	SysNtReadFile	proc
		mov r10, rcx
		mov eax, 6
		syscall
		ret
	SysNtReadFile endp
end
