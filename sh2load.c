#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <malloc.h>
#include <limits.h>
#include <sys/ptrace.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <sys/user.h>
#include <unistd.h>
#include <dlfcn.h>
#include "proc.h"
#include "vmap.h"

#ifdef __i386__

char shellcode[] = {
	0x6A,0x01,0xEB,0x07,0xFF,0xD3,0x83,0xC4,
	0x08,0x5B,0xC3,0xE8,0xF4,0xFF,0xFF,0xFF,
	0x90
};

#define STR_OFFSET 0x10
#define SHELL_SIZE 0x10

#elif __x86_64__

char shellcode[] = {
	0x48,0x31,0xF6,0xEB,0x08,0x5F,0x48,0xFF,
	0xC6,0xFF,0xD3,0x5B,0xC3,0xE8,0xF3,0xFF,
	0xFF,0xFF,0x90
};

#define STR_OFFSET 0x12
#define SHELL_SIZE 0x12

#endif

void emu_push(pid_t pid,struct user_regs_struct *regs,
	unsigned long value)
{
#ifdef __i386__
	regs->esp -= sizeof(unsigned long);
	if(ptrace(PTRACE_POKEDATA,pid,regs->esp,value) < 0)
		perror("ptrace_pokedata");
#elif __x86_64__
	regs->rsp -= sizeof(unsigned long);
	if(ptrace(PTRACE_POKEDATA,pid,regs->rsp,value) < 0)
		perror("ptrace_pokedata");
#endif
}

unsigned long getfuncaddr(const char* name)
{
	void* mod;
	if(!(mod = dlopen("libc.so.6",RTLD_LAZY)))
		return -1;
	return (unsigned long)dlsym(mod,name);
}

int main(int argc,char** argv)
{
	pid_t pid = atoi(argv[1]);
	struct user_regs_struct regs;
	struct stat st;
	vmap_t shell,libc,local_libc;
	unsigned long dlpn_off,dlpn_addr;
	char* local_shell;
	size_t path_size,total_size;
	int pd,wr;
	char filename[PATH_MAX];
	
	
	if(vmap_reqeust(pid,VMAP_WALK_SHELL,&shell) < 0)
	{
		fputs("[-] Place for shellcode not found!\n",stderr);
		exit(0);
	}
	
	if(vmap_reqeust(pid,VMAP_WALK_LIBC,&libc) < 0)
	{
		fputs("[-] Libc not found!\n",stderr);
		exit(0);
	}
	
	if(vmap_reqeust(getpid(),VMAP_WALK_LIBC,&local_libc) < 0)
	{
		fputs("[-] Local libc not found!\n",stderr);
		exit(0);
	}
	
	suspend_proc(pid,true);
	
	if((pd = open_proc(pid)) < 0)
	{
		perror("open_proc");
		suspend_proc(pid,false);
		exit(1);
	}
	
	realpath(argv[2],filename);
	path_size = strlen(filename) + 1;
	total_size = path_size + SHELL_SIZE;
	
	local_shell = (char*)malloc(total_size);
	if(!local_shell)
	{
		perror("malloc");
		suspend_proc(pid,false);
		exit(1);
	}
	
	memcpy((void*)local_shell,shellcode,SHELL_SIZE);
	memcpy((void*)(local_shell+STR_OFFSET),filename,path_size);
	
	printf("%lx-%lx\n",shell.vm_start,shell.vm_end);
	
	if((wr = pwrite(pd,(void*)local_shell,
		total_size,(off_t)shell.vm_start)) < 0)
	{
		perror("pwrite");
		goto ex;
	}
	else
		printf("[+] Shellcode written %d\n",wr);
	
	if(!(dlpn_addr = getfuncaddr("__libc_dlopen_mode")))
	{
		perror("getfuncaddr");
		goto ex;
	}
	
	printf("__libc_dlopen_mode %lx\n",dlpn_addr);
	dlpn_off = dlpn_addr - local_libc.vm_start;
	printf("offset %lx\n",dlpn_off);
	dlpn_addr = dlpn_off + libc.vm_start;
	printf("remote __libc_dlopen_mode %lx\n",dlpn_addr);
	
	ptrace(PTRACE_GETREGS,pid,0,&regs);
#ifdef __i386__
	emu_push(pid,&regs,regs.eip);
	emu_push(pid,&regs,regs.ebx);
	
	regs.eip = (unsigned long)shell.vm_start+2;
	regs.ebx = (unsigned long)dlpn_addr;
#elif __x86_64__
	emu_push(pid,&regs,regs.rip);
	emu_push(pid,&regs,regs.rbx);
	
	regs.rip = (unsigned long)shell.vm_start+2;
	regs.rbx = (unsigned long)dlpn_addr;
#endif

	ptrace(PTRACE_SETREGS,pid,0,&regs);
ex:
	suspend_proc(pid,false);
	
	free((void*)local_shell);
	close_proc(pd);
	return 0;
}
