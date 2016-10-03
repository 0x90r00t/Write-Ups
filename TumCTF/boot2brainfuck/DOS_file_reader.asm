BITS    16
ORG     0x100

        mov ah, 0x3D            ; DOS open interrupt
        mov al, 0               ; mode: read-only
        mov dword [bp+0x200], "A:"
        mov dword [bp+0x202], 0x465C
        mov dword [bp+0x204], "LA"
        mov dword [bp+0x206], "G."
        mov dword [bp+0x208], "TX"
        mov word [bp+0x20a], 0x54
        mov si, 0               ; counter for print
print:
        mov ah, 0x2             ; DOS write interrupt
        mov dl, [bp+0x200+si]   ; character to write
        int 0x21                ; DOS interrupt
        inc si                  ; inc counter
        cmp si, 12              ; we print 12 chars
        jl print                ; loop
        mov al, 0               ; mode: read-only
        mov ah, 0x3D            ; DOS open interrupt
        lea dx, [bp+0x200]      ; filename
        int 21h                 ; DOS interrupt
        mov [bp+0x19F], ax      ; save handle
readfile:
        mov bx, [bp+0x19F]      ; get handle
        mov ah, 0x3F            ; DOS read file interrupt
        mov cx, 1               ; number of bytes to read
        lea dx, [bp+0x150]      ; buffer
        int 21h                 ; DOS interrupt
        cmp ax, cx              ; check if EOF
        jne exit                ; exit if EOF
        mov ah, 0x2             ; DOS write interrupt
        mov dl, [bp+0x150]      ; character to write
        int 21h                 ; DOS interrupt
        jmp readfile            ; loop till EOF
exit:
        mov ah, 4ch             ; DOS exit interrupt
        mov al, 0               ; exit code
        int 21h                 ; DOS interrupt
