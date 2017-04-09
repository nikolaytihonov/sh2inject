# sh2load
Linux Shared Library Injection Tool (inject *.so files into process). It's not LD_PRELOAD dirty trick, IN RUN-TIME!

Usage: ./sh2load [pid] [path_to_lib]
(You will check architecture of process and library!)

# Architecture
Now supporting these architectures:
1. x86-64
2. x86

# Compiling
gcc sh2load.c proc. vmap.c -o sh2load -ldl

or 32 bit (This need to inject 32 bit libs to 32 bit processes)

gcc -m32 sh2load.c proc. vmap.c -o sh2load -ldl

# Some example of library
```
#include <stdio.h>

void __entry(void) __attribute__((constructor));

void __entry(void)
{
	puts("Hello World from Shared Library!");
}
```
And compile it: gcc libtest.c -fPIC -shared -o libtest.so

//Some ideas (aka iterating /proc/$pid/maps) is not absolute my. I'm just reimplemented by my hand and mind. But, it works! Enjoy and get fun!
