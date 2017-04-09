use64

xor rsi,rsi
jmp _text
_code:

pop rdi
inc rsi
call rbx

pop rbx
ret

_text:
call _code
db "/something/library/path",0
