.code

gadget PROC
    ; Push rdi onto the stack
    push rdx

    ; Call some function (this is just an example label; replace it with the actual function you want to call)
    call rax

    ; The return value is already in rax (as per calling convention)

    ; Return to the caller
    ret
gadget ENDP

END
