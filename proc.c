#include "proc.h"

int is_numeric(char* s)
{
	while(*s)
	{
		if(!isdigit(*s))
			return 0;
		s++;
	}
	return 1;
}

int walk_proc(walk_proc_callback func,void *data)
{
	struct dirent* dr;
	DIR* d;
	if(!(d = opendir("/proc")))
		return -1;
	while((dr = readdir(d)))
	{
		if(dr->d_type == DT_DIR)
		{
			if(is_numeric(dr->d_name))
			{	
				if(func(atoi(dr->d_name),data))
					return 1;
			}
		}
	}
	closedir(d);
	return 0;
}

int walk_thread(pid_t pid,walk_thread_callback func,void *data)
{
	struct dirent* dr;
	DIR* d;
	char path[256];
	sprintf(path,"/proc/%d/task",pid);
	if(!(d = opendir(path)))
		return -1;
	while((dr = readdir(d)))
	{
		if(dr->d_type == DT_DIR)
		{
			if(is_numeric(dr->d_name)==1)
			{
				if(func(atoi(dr->d_name),data))
					return 1;
			}
		}
	}
	closedir(d);
	return 0;
}

int suspend_proc_callback(pid_t tid,void *data)
{
	int status;
	if(*(bool*)data == true)
	{
		ptrace(PTRACE_ATTACH,tid,0,0);
		waitpid(tid,&status,0);
	}
	else
	{
		ptrace(PTRACE_DETACH,tid,0,0);
		waitpid(tid,&status,0);
	}
	return 0;
}

int suspend_proc(pid_t pid,bool suspend)
{
	return walk_thread(pid,&suspend_proc_callback,(void*)&suspend);
}

int open_proc(pid_t pid)
{
	char path[256];
	sprintf(path,"/proc/%d/mem",pid);
	return open(path,O_RDWR);
}

void close_proc(int pd)
{
	close(pd);
}
