#include <string.h>
#include <errno.h>

#define SGREP_LIBRARY
#include "sgrep.h"

#if HAVE_UNIX
/* For open */
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

/*
 * Cygwin32 requires O_BINARY flag to open()
 * In other systems it can safely be ignored
 */
# ifndef O_BINARY
#  define O_BINARY 0
# endif

#endif


#if HAVE_MMAP
# include <unistd.h>
#elif HAVE_WIN32
# include <windows.h>
#endif

#if HAVE_SYS_MMAN_H
# include <sys/mman.h>
#endif


/* It is possible (and in fact quite easy) to implement
 * index lookups without memory mapping. However every
 * decent system should support it, so i'm relaying on
 * mmap() at least for now.
 * Returns 0 on error.
 */
size_t map_file(SgrepData *sgrep,const char *filename,void **map) {
#if HAVE_MMAP
    int fd;
    int len;
    fd=open(filename,O_RDONLY);
    if (fd<0) {
	sgrep_error(sgrep,"Failed to open file '%s':%s\n",
		filename,strerror(errno));
	*map=NULL;
	return 0;
    }
    len=lseek(fd,0,SEEK_END);
    if (len<0) {
	sgrep_error(sgrep,"lseek '%s':%s",filename,strerror(errno));
	close(fd);
	*map=NULL;
	return 0;
    }
    /* fprintf(stderr,"Mapping '%s' (%dK)\n",filename,len/1024); */
/* Older Linux systems don't define MAP_FAILED */
#ifndef MAP_FAILED
#define MAP_FAILED (-1L)
#endif
    *map=mmap(NULL,len,PROT_READ,MAP_SHARED,fd,0);
    close(fd);
    if (*map==NULL || (*map)==(void *)MAP_FAILED) {
	sgrep_error(sgrep,"mmap '%s':%s\n",
		    filename,strerror(errno));
	*map=NULL;
	return 0;
    }
    return len;
#elif HAVE_WIN32
	HANDLE file;
    HANDLE mapping;
	LPVOID pointer;
	DWORD size;
	file=CreateFile(filename,GENERIC_READ,FILE_SHARE_READ,NULL,
			OPEN_EXISTING,0,NULL);
	if (file==INVALID_HANDLE_VALUE) {
		sgrep_error(sgrep,"Failed to open '%s':%d\n",filename,GetLastError());
		*map=NULL;
		return 0;
	}
	size=GetFileSize(file,NULL);
	if (size==0xFFFFFFFF) {
		sgrep_error(sgrep,"GetFileSize: %d\n",GetLastError());
		*map=NULL;
		CloseHandle(file);
		return 0;
	}
	if (size==0) {
		sgrep_error(sgrep,"Zero length index file '%s'\n");
		*map=NULL;
		CloseHandle(file);
		return 0;
	}
	mapping=CreateFileMapping(file,NULL,PAGE_READONLY,0,0,NULL);
	if (mapping==NULL) {
		sgrep_error(sgrep,"CreateFileMapping: %d\n",GetLastError());
		*map=NULL;
		CloseHandle(file);
		return 0;
	};
	pointer=MapViewOfFile(mapping,FILE_MAP_READ,0,0,0);
	if (pointer==NULL) {
		sgrep_error(sgrep,"MapViewOfFile: %d\n",GetLastError());
		CloseHandle(mapping);
		CloseHandle(file);
		*map=NULL;
		return 0;
	}
	*map=pointer;
	CloseHandle(mapping);
	CloseHandle(file);
	return size;
#else
#error "Don't know howto mmap"
#endif
}



int unmap_file(SgrepData *sgrep,void *map, size_t size) {
#if HAVE_MMAP
    /* FIXME: glibc header have a bug: munmap takes caddr_t parameter
     * instead of void *, which breaks with strict C++ type checking */
    if (munmap(map,size)<0) return SGREP_ERROR;
    return SGREP_OK;
#elif HAVE_WIN32
	if (UnmapViewOfFile(map)) {
		return SGREP_OK;
	} else {
		sgrep_error(sgrep,"UnMapViewOfFile: %s\n",GetLastError());
		return SGREP_ERROR;
	}
#else
#error "Needs unmap_file() implementation"
#endif
}

/*
 * Temporary file handling. These functions might seem to be overkill,
 * but i wanted to have portable and reliable temp file handling..
 * The ANSI tmpfile functions we're not enough */
struct TempFileStruct {  
    SgrepData *sgrep;
    char *file_name;
    FILE *stream;
    TempFile *next;
    TempFile *prev;
};

TempFile *create_named_temp_file(SgrepData *sgrep) {
#if HAVE_UNIX
    const char *prefix;
    SgrepString *file_name;
    char tmp[50];
    int fd;
    static int i=0;
    int j;
#endif

    /* The things which WIN32 and unix have in common  */
    TempFile *temp_file;

    temp_file=sgrep_new(TempFile);
    temp_file->sgrep=sgrep;
    temp_file->stream=NULL;
    temp_file->prev=NULL;
    
#if HAVE_UNIX
    file_name=new_string(sgrep,1024);
    prefix=getenv(ENV_TEMP);
    if (!prefix) {
	prefix=DEFAULT_TEMP_DIR;
    }
    for(j=0;temp_file->stream==NULL && j<1000;j++) {
	i++;
	string_clear(file_name);
	string_cat(file_name,prefix);
	string_cat(file_name,"/");
	string_cat(file_name,TEMP_FILE_PREFIX);
	sprintf(tmp,"%d-%d",getpid(),i);
	string_cat(file_name,tmp);
	string_cat(file_name,TEMP_FILE_POSTFIX);
	fd=open(string_to_char(file_name),O_RDWR|O_BINARY|O_CREAT|O_EXCL,0600);
	if (fd>=0) {
	    temp_file->stream=fdopen(fd,"wb+");
	}
    }
    if (temp_file->stream==NULL) {
	sgrep_error(sgrep,"Failed to create temp file '%s': %s\n",
		    string_to_char(file_name),strerror(errno));
	sgrep_free(temp_file);
	delete_string(file_name);
	return NULL;
    }
    temp_file->file_name=sgrep_strdup(string_to_char(file_name));
    delete_string(file_name);
    /* sgrep_error(sgrep,"tempfile: %s(%d)\n",temp_file->file_name,fd); */
#elif HAVE_WIN32
	temp_file->file_name=(char *)sgrep_malloc(L_tmpnam);
	tmpnam(temp_file->file_name);
	temp_file->stream=fopen(temp_file->file_name,"wb+");
	if (temp_file->stream==NULL) {
		sgrep_error(sgrep,"Failed to create temp file '%s': %s\n",
		    temp_file->file_name,strerror(errno));		
		sgrep_free(temp_file->file_name);
		sgrep_free(temp_file);
		return NULL;
	}
	/* fprintf(stderr,"tempfile: %s\n",temp_file->file_name); */
#else
#error "needs create_temp_file for target"
#endif

	temp_file->next=sgrep->first_temp_file;
    if (temp_file->next) temp_file->next->prev=temp_file;
    sgrep->first_temp_file=temp_file;
	return temp_file;
}

TempFile *create_temp_file(SgrepData *sgrep) {
#if HAVE_UNIX
    TempFile *temp_file=create_named_temp_file(sgrep);
    if (!temp_file) return NULL;
    if (remove(temp_file->file_name)==0) {
	sgrep_free(temp_file->file_name);
	temp_file->file_name=NULL;
    } else {
	sgrep_error(sgrep,"Failed to unlink tempfile '%s':%s\n",
		    temp_file->file_name,strerror(errno));
    }
    return temp_file;
#else
    return create_named_temp_file(sgrep);
#endif
}

FILE *temp_file_stream(TempFile *temp_file) {
    assert(temp_file);
    return temp_file->stream;
}

const char *temp_file_name(TempFile *temp_file) {
    assert(temp_file);
    return temp_file->file_name;
}

int delete_temp_file(TempFile *temp_file) {
    SGREPDATA(temp_file);
    fclose(temp_file->stream);
    if (temp_file->file_name) {
	if (remove(temp_file->file_name)) {
	    sgrep_error(sgrep,"Failed to remove temp file '%s':%s\n",
			temp_file->file_name,strerror(errno));
	}
	sgrep_free(temp_file->file_name);
	temp_file->file_name=NULL;
    }
    if (sgrep->first_temp_file==temp_file) {
	sgrep->first_temp_file=temp_file->next;
    }
    if (temp_file->next) {
	temp_file->next->prev=temp_file->prev;
    }
    if (temp_file->prev) {
	temp_file->prev->next=temp_file->next;
    }
    sgrep_free(temp_file);
    return SGREP_OK;
}
/* 
 * Reads stdin to a temp file. Leaves temp file open and stdin_fd pointing
 * to it. File name will be NULL. Unlinks temp file, so that it will be 
 * removed when program exits.
 * returns size of input file read
 */
TempFile *temp_file_read_stdin(SgrepData *sgrep)
{
	char buf[8192];
	int r,w;
	TempFile *temp;
	FILE *temp_stream;
	
	if (sgrep->stdin_temp_file) {
	    /* Already read */
	    sgrep_error(sgrep,"stdin already used\n");
	    return NULL;
	}

	temp=create_named_temp_file(sgrep);
	if (!temp) return NULL;

	temp_stream=temp_file_stream(temp);
	
	do {
	    r=fread(buf,1,8192,stdin);
	    if (r>0) {
		w=fwrite(buf,1,r,temp_stream);
	    }
	} while (r>0 && w==r && !feof(stdin));
	if (ferror(stdin)) {
	    sgrep_error(sgrep,"Failed to read stdin: %s\n",strerror(errno));
	    delete_temp_file(temp);
	    return NULL;
	}
	if (ferror(temp_stream) || fflush(temp_stream) || 
	    ferror(temp_stream) || fseek(temp_stream,0,SEEK_SET)!=0) {
	    sgrep_error(sgrep,"Failed to write stdin to temp file: %s\n",
			strerror(errno));
	    delete_temp_file(temp);
	    return NULL;
	}
	sgrep->stdin_temp_file=temp;
	return temp;
}

#if MEMORY_DEBUG

#undef free
#undef malloc
#undef realloc
#undef calloc
#undef perror

typedef struct MemoryBlockStruct MemoryBlock;
struct MemoryBlockStruct {
    int magic;
    const char *file;
    int line;
    size_t size;
    struct MemoryBlockStruct *prev;
    struct MemoryBlockStruct *next;
};

/*
 * This is malloc which prints error message and exists if memory couldn't
 * be allocated.
 * Also can keep track of allocated memory blocks for the DLL version
 */
void *sgrep_debug_malloc(SgrepData *sgrep,size_t size, 
			 const char *file, int line)
{
    MemoryBlock *block;
    if (size==0) return NULL;
    if (!sgrep) {
	void *ptr;
	ptr=malloc(size);
	if (!ptr) {
	    perror("malloc");
	    abort();
	}
	return ptr;
    }
    block=(MemoryBlock *)malloc(sizeof(MemoryBlock)+size);
    if (block==NULL) {
	perror("malloc");
	abort();
    }

    block->magic=91172;
    block->file=file;
    block->line=line;

    block->size=sizeof(MemoryBlock)+size;

    block->next=sgrep->m_blocks;
    block->prev=NULL;    
    if (sgrep->m_blocks) sgrep->m_blocks->prev=block;
    sgrep->m_blocks=block;

    stats.memory_blocks++;
    stats.memory_allocated+=block->size;
    if (stats.memory_allocated>stats.peak_memory_usage) {
	stats.peak_memory_usage=stats.memory_allocated;
    }
    return block+1;
}

void *sgrep_debug_calloc(SgrepData *sgrep,size_t nmemb,size_t size) {
    void *mem;
    mem=sgrep_malloc(nmemb*size);
    memset(mem,0,nmemb*size);
    return mem;
}

void sgrep_debug_free(SgrepData *sgrep, void *ptr) {
    MemoryBlock *block;
    assert(ptr!=NULL);
    if (!sgrep) {
	free(ptr);
	return;
    }
    block=((MemoryBlock *)ptr)-1;
    assert(block->magic==91172);
    if (block->next) {
	block->next->prev=block->prev;
    }
    if (block->prev) {
	block->prev->next=block->next;
    } else {
	/* First block in list */
	assert(sgrep->m_blocks==block);
	sgrep->m_blocks=block->next;
	if (sgrep->m_blocks) sgrep->m_blocks->prev=NULL;
    }
    stats.memory_blocks--;
    stats.memory_allocated-=block->size;
    block->magic=0;
    block->file=NULL;
    block->line=0;
    free(block);
}

void sgrep_free_all(SgrepData *sgrep) {
    assert(sgrep);
    while(sgrep->m_blocks!=NULL) {
	sgrep_free(sgrep->m_blocks+1);
    }
    assert(stats.memory_blocks==0 && stats.memory_allocated==0);
}

/*
 * This realloc, which prints error message and exits, if memory couldn't
 * be reallocated. Keeps track of how much memory has been allocated
 */
void *sgrep_debug_realloc(SgrepData *sgrep,void *ptr,size_t size)
{
    MemoryBlock *old_block;
    MemoryBlock *new_block;
    if (ptr==NULL) return sgrep_malloc(size);
    if (size==0) {
	sgrep_free(ptr);
	return NULL;
    }
    if (!sgrep) {	
	void *r=realloc(ptr,size);
	if (!r) {
	    perror("realloc");
	    abort();
	}
	return r;
    }
    old_block=((MemoryBlock *)ptr)-1;
    assert(old_block->magic==91172);
	old_block->magic=0;
    new_block=(MemoryBlock *)realloc(old_block,size+sizeof(MemoryBlock));
	new_block->magic=91172;

    if (new_block==NULL)
    {
	perror("realloc");
	abort();
    }
    if (new_block!=old_block) {
	if (new_block->next) new_block->next->prev=new_block;
	if (new_block->prev) new_block->prev->next=new_block;
  	if (sgrep->m_blocks==old_block) {
		sgrep->m_blocks=new_block;
	}  
    }
    stats.reallocs++;
    stats.memory_allocated+=size+sizeof(MemoryBlock)-new_block->size;
    new_block->size=size+sizeof(MemoryBlock);
    if (stats.memory_allocated>stats.peak_memory_usage) {
	stats.peak_memory_usage=stats.memory_allocated;
    }
    return new_block+1;
}

char *sgrep_debug_strdup(SgrepData *sgrep,const char *str,
			 const char *file, int line) {
    int l;
    char *new_str;
    l=strlen(str);
    new_str=(char *)sgrep_debug_malloc(sgrep,l+1,file,line);
    memcpy(new_str,str,l+1);
    return new_str;
}

void check_memory_leaks(SgrepData *sgrep) {
    int leaks=0;    
    MemoryBlock *block;
    assert(sgrep);
    if (stats.memory_blocks>0) {
	fprintf(sgrep->progress_stream,
		"Memory leak: %d blocks having %d bytes total size\n",
		stats.memory_blocks,stats.memory_allocated);

	fprintf(sgrep->progress_stream,"<LEAK_SPOTS>\n");
	for(block=sgrep->m_blocks;block && leaks<15;block=block->next) {
	    leaks++;
	    fprintf(sgrep->progress_stream,
		    "\t%s:%d: %d bytes\n",block->file,block->line,block->size);
	}
	fprintf(sgrep->progress_stream,"</LEAK_SPOTS>\n");
    }
}

#else /* MEMORY_DEBUG */

void check_memory_leaks(SgrepData *sgrep) {
    /* Nothing */
}

#endif /* MEMORY_DEBUG */
