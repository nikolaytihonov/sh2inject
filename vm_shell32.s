use32

push 1
jmp _text
_code:

call ebx
add esp,8
pop ebx
ret

_text:
call _code
db "/something/library/path",0 ;offset 0x10
