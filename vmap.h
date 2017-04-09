#ifndef __VMAP_H
#define __VMAP_H

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>

typedef enum {
	VMAP_WALK_SHELL,
	VMAP_WALK_LIBC,
} request_t;

typedef enum {
	VMAP_OK,
	VMAP_NOTFOUND,
} status_t;

typedef struct {
	uintptr_t vm_start;
	uintptr_t vm_end;
	char perms[5];
	uint32_t magic_num;
	char path[256];
} vmap_t;

typedef struct {
	request_t type;
	status_t status;
	vmap_t *map;
} vmap_request_t;

typedef int (*walk_map_callback)(vmap_t *map,void *arg);

void vmap_parse(vmap_t* map,const char* str);
int vmap_walk(pid_t pid,walk_map_callback func,void *arg);
int vmap_reqeust(pid_t pid,request_t what,vmap_t *map);

#endif
