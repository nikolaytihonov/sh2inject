#include "vmap.h"

void vmap_parse(vmap_t* map,const char* str)
{
	sscanf(str,"%lx-%lx %s %08d %*02d:%*02d %*s %s",
		&map->vm_start,&map->vm_end,map->perms,
		&map->magic_num,map->path);
}

int vmap_walk(pid_t pid,walk_map_callback func,void *arg)
{
	char buf[256];
	char path[64];
	vmap_t map;
	FILE* fmap;
	
	sprintf(path,"/proc/%d/maps",pid);
	if(!(fmap = fopen(path,"rb")))
		return -1;
		
	while(fgets(buf,256,fmap) != NULL)
	{
		vmap_parse(&map,buf);
		if(func(&map,arg))
			return 1;
	}
	return 0;
}

int walk_map_func(vmap_t *map,void *arg)
{
	vmap_request_t *vreq = (vmap_request_t*)arg;
	vreq->status = VMAP_NOTFOUND;
	if(vreq->type == VMAP_WALK_SHELL && strchr(map->perms,'x'))
	{
		vreq->status = VMAP_OK;
		memcpy(vreq->map,map,sizeof(vmap_t));
		return 1;
	}
	else if(vreq->type == VMAP_WALK_LIBC && strstr(map->path,"libc-"))
	{
		vreq->status = VMAP_OK;
		memcpy(vreq->map,map,sizeof(vmap_t));
		return 1;
	}
	return 0;
}

int vmap_reqeust(pid_t pid,request_t what,vmap_t *map)
{
	vmap_request_t vreq;
	
	vreq.type = what;
	vreq.map = map;
	vmap_walk(pid,&walk_map_func,(void*)&vreq);
	if(vreq.status == VMAP_OK)
		return 0;
	
	return -1;
}
