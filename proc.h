#ifndef __PROC_H
#define __PROC_H

#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <string.h>
#include <sys/ptrace.h>
#include <sys/wait.h>
#include <unistd.h>
#include <dirent.h>
#include <fcntl.h>

typedef int (*walk_proc_callback)(int pid,void *data);
typedef int (*walk_thread_callback)(pid_t tid,void *data);

int walk_proc(walk_proc_callback func,void *data);
int walk_thread(pid_t pid,walk_thread_callback func,void *data);

int suspend_proc(pid_t pid,bool suspend);

int open_proc(pid_t pid);
void close_proc(int pd);

#endif
