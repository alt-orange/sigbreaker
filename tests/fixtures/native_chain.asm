; Two runtime-function regions sharing a stack frame. The primary must stay
; fixed; the secondary exercises a CHAININFO unwind record after relocation.
PUBLIC chained_probe
PUBLIC chained_body
PUBLIC tail_probe
EXTERN __imp_lstrlenA:QWORD
.const
text_one DB "three",0
text_two DB "four",0
text_other DB "five!",0
.code
chained_probe PROC
    push rbx
    sub rsp, 20h
    jmp chained_body
primary_end LABEL BYTE
chained_probe ENDP

chained_body PROC
    cmp ecx, 1
    je case_one
    cmp ecx, 2
    je case_two
    call rdx
    jmp body_done
case_one:
    mov eax, 111
    jmp body_done
case_two:
    mov eax, 222
body_done:
    add rsp, 20h
    pop rbx
    ret
body_end LABEL BYTE
chained_body ENDP

tail_probe PROC
    push rbx
    sub rsp, 20h
    cmp ecx, 0
    je tail_zero
    cmp ecx, 1
    je tail_one
    lea rcx, text_other
    jmp tail_done
tail_zero:
    lea rcx, text_one
    jmp tail_done
tail_one:
    lea rcx, text_two
tail_done:
    add rsp, 20h
    pop rbx
    jmp QWORD PTR [__imp_lstrlenA]
tail_end LABEL BYTE
tail_probe ENDP

_XDATA SEGMENT READONLY ALIGN(4) ALIAS(".xdata")
primary_unwind LABEL BYTE
    DB 1, 5, 2, 0
    DB 5, 32h, 1, 30h
body_unwind LABEL BYTE
    DB 21h, 0, 0, 0
    DD imagerel chained_probe, imagerel primary_end, imagerel primary_unwind
_XDATA ENDS
_PDATA SEGMENT READONLY ALIGN(4) ALIAS(".pdata")
    DD imagerel chained_probe, imagerel primary_end, imagerel primary_unwind
    DD imagerel chained_body, imagerel body_end, imagerel body_unwind
    DD imagerel tail_probe, imagerel tail_end, imagerel primary_unwind
_PDATA ENDS
END
