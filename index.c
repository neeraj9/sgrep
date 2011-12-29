/*
 * Index file format, index file generation and index file usage
 * are complex operations indeed. You have been warned.
 *
 * This stuff really would need some documentation
 */

/*
 * Here are some design principles:
 * - There will be one IndexBuffer for every index term. That's why
 *   IndexBufferStruct must be kept small
 * - There will migh be millions of postings in one IndexBuffer.
 *   That's why the memory needed by one posting must be kept small
 *   (compression is used)
 * - The size of the whole index will be greater than available RAM-memory.
 *   So it cannot be constructed in main memory. It will be divided
 *   to memory loads.
 */

/*
 * Here are some assumptions:
 * - The underlying OS supports memory mapped files
 * - There is enough main memory for one IndexBufferStruct and for
 *   index spool (INDEX_SPOOL_SIZE) for each term
 */

#include <stdio.h>
#include <limits.h>
#include <string.h>
#include <errno.h>

#define SGREP_LIBRARY

#include "sgrep.h"

/*
 * How many regions we need to handle, before we add a dot
 */
#define DOT_REGIONS (1<<17) /* 65536*2 */

#define INDEX_VERSION_MAGIC ("sgrep-index v0")

/* If we would need larger index than MAX_INDEX_SIZE we would have
 * to deal with 64 bit wide integers.
 */
#define MAX_INDEX_SIZE (INT_MAX)
#define EXTERNAL_INDEX_BLOCK_SIZE 32
#define max_term_len 256

/* We will run out of filedescriptors, before running out of memory
 * loads. Anyway, this enough for creating MAX_INDEX_SIZE sized index
 * with 32M memory load.
 */
#define MAX_MEMORY_LOADS 256

#define INDEX_BUFFER_ARRAY_SIZE 1024

const static IndexOptions default_index_options= {
    NULL,IM_NONE,0,0,NULL,NULL,DEFAULT_HASH_TABLE_SIZE,
    DEFAULT_INDEXER_MEMORY,NULL
};


struct IndexBlock {
    int next;
    unsigned char buf[EXTERNAL_INDEX_BLOCK_SIZE];
};

struct ExternalIndexBuffer {
    int first;
    int current;
    int bytes;
};
/* #define INTERNAL_BLOCK_SIZE (sizeof(struct ExternalIndexBuffer)) */
#define INTERNAL_INDEX_BLOCK_SIZE 12

struct IndexBufferStruct {
    char *str;
    struct IndexBufferStruct *next;
    union {
	/* This struct is used when building index and all entries of a 
	 * term fit inside IndexBuffer */
	struct {
	    unsigned char ibuf[INTERNAL_INDEX_BLOCK_SIZE];
	} internal;
	/* This struct is used when building index and entries of a term
	 * do not fit inside IndexBuffer */
	struct ExternalIndexBuffer external;
	/* This is used, when reading index from a file */
	struct {
	    const unsigned char *buf;
	    int ind;
	} map;
    } list;
    /* Last index added to this buffer. This will be zero when the buffer
     * is created, INT_MAX when the buffer has been scanner and -1
     * if this buffer corresponds to stop word (and therefore is not used )
     */
    int last_index;
    int saved_bytes; /* How many bytes of this entry have been saved to a
		      * memory load file */
    /* block_used will >= 0 for internal buffer, <0 for external buffers
     * and SHORT_MIN  when reading */
    short block_used;
    short last_len;
    unsigned char lcp;
};
typedef struct IndexBufferStruct IndexBuffer;


struct IndexReaderStruct {
    SgrepData *sgrep;
    const char *filename;
    void *map;
    size_t size;
    int len;    
    const unsigned char *array;
    const void *entries;    
};

struct IndexBufferArray {
    IndexBuffer bufs[INDEX_BUFFER_ARRAY_SIZE];
    struct IndexBufferArray *next;
};

typedef struct IndexWriterStruct {
    struct SgrepStruct *sgrep;
    
    const IndexOptions *options;

    /* FileList of the indexed files */
    FileList *file_list;

    /* To speed up index buffer allocation and to reduce memory usage of
     * the index buffers, they are allocated in chunks. */
    struct IndexBufferArray *free_index_buffers;
    int first_free_index_buffer;

    /* Points to hash table of IndexBuffers when scanning indexed files */
    int hash_size; /* Size of the hash table */
    IndexBuffer **htable;
    /* Points to list of sorted IndexBuffers when writing index file */
    IndexBuffer *sorted_buffers;

    /* Size, usage and pointer to postings spool (the one in main memory) */
    int spool_size;
    int spool_used;
    struct IndexBlock *spool;
    
    /* Array of memory load files */
    TempFile *memory_load_files[MAX_MEMORY_LOADS];
    int memory_loads;
    
    /* The stream to which index is written */
    FILE *stream;

    
    /* Statistics */
    int terms;
    int postings;
    int total_postings_bytes;
    int total_string_bytes;
    int strings_lcps_compressed;
    int entry_lengths[8];
    int flist_start;
    int flist_size;
    int total_index_file_size;

    int failed;
} IndexWriter;


/*
 * Used for creating IndexEntryLists
 */
struct IndexEntryListStruct {
    int hits;
    IndexReader *reader;
    IndexEntry *first;
    IndexEntry *last;
};

struct IndexEntryStruct {
    char *term;
    const unsigned char *postings;
    struct IndexEntryStruct *next;
};

/*
 * Used for reading index postings
 */
struct SortingReaderStruct {
    Region *regions[32];
    int sizes[32];
    int lists_merged;
    int regions_merged;
    int max;

    Region one;
    Region *saved_array;
    int saved_size;
    int dots;
};


/*
 * Looking up something in index requires one of these
 */
struct LookupStruct {
    SgrepData *sgrep;
    const char *begin;
    const char *end;
    IndexReader *map;
    void (*callback)(const char *str, const unsigned char *regions, 
		     struct LookupStruct *data);    
    int stop_words;
    union {
	/* This one is for looking up only entries */
	struct IndexEntryListStruct *entry_list;
	/* This one is for creating possibly unsorted region list from all
	 * postings */
	RegionList *reader;
	/* This is used for sorting postings while reading them */
	struct SortingReaderStruct sorting_reader;
	/* This is for dumping postings to a file stream */
	FILE *stream;
    } data;
};

/*
 * The real stuff 
 */
 

static int put_int(int i,FILE* stream) {
    putc(i>>24,stream);
    putc(i>>16,stream);
    putc(i>>8,stream);
    putc(i&255,stream);
    return 4;
}

static int get_int(const unsigned char *ptr, int ind) {
    ptr+=ind*4;
    return (ptr[0]<<24) | (ptr[1]<<16) | (ptr[2]<<8) | ptr[3];
}

/*
 * Writes postings of from given IndexBuffer to given stream.
 * Does NOT check write errors: they have to be checked later.
 */
static int fwrite_postings(IndexWriter *writer, IndexBuffer *tmp,
			   FILE *stream) {
    int bytes=0;
    /* Now the regions */
    if (tmp->block_used==0) {
	/* This is possible, when this buffer was written out 
	 * in some previous memory load, and there has been no new
	 * entries in this buffer since or when this is a stop word
	 * buffer and therefore contains no entries */
	return 0;
    } else if (tmp->block_used>0) {
	bytes+=tmp->block_used;
	fwrite(tmp->list.internal.ibuf,tmp->block_used,1,stream);
    } else {
	int esize;
	struct IndexBlock *ind=&writer->spool[tmp->list.external.first];
	esize=tmp->list.external.bytes;
	bytes=esize;
	while(ind->next!=INT_MIN) {
	    esize-=EXTERNAL_INDEX_BLOCK_SIZE;
	    fwrite(ind->buf,EXTERNAL_INDEX_BLOCK_SIZE,1,stream);
	    ind=&writer->spool[ind->next];
	}
	assert(esize<=EXTERNAL_INDEX_BLOCK_SIZE);
	fwrite(ind->buf,esize,1,stream);
    }
    return bytes;
}

/* FIXME: needs better hash function */
unsigned int hash_function(int size,const char *str) {
    int i;
    unsigned int r=0;

    for(i=0;str[i];i++) {
    	r=((unsigned char)str[i])+61*r;
    }
    /* printf("%s=%d,",str,r%size); */
    return r%size;
}
    
void display_index_statistics(IndexWriter *writer) {
    int i;
    int size;
    FILE *f;
    f=writer->sgrep->progress_stream;
    size=writer->spool_size*sizeof(struct IndexBlock);
    fprintf(f,"Indexer memory usage:\n");
    fprintf(f,"%dK bytes postings, %dK postings spool size, %dK used\n",
	    writer->total_postings_bytes/1024,
	    size/1024,
	    writer->spool_used/1024);
    fprintf(f,"%d individual terms of %d term postings (%d%%)\n",
	    writer->terms,writer->postings,
	    writer->terms*100/writer->postings);
    fprintf(f,"Postings lengths:\n");
    for(i=0;i<8;i++) {
	if (writer->entry_lengths[i]>0) {
	    fprintf(f,"%8d:%8d, %8dK (%d%%)\n",i+1,
		   writer->entry_lengths[i],
		   (i+1)*writer->entry_lengths[i]/1024,
		   (i+1)*writer->entry_lengths[i]*100/writer->total_postings_bytes);
	}
    }
    fprintf(f,"Hash array size %dK\n",
	   writer->hash_size*sizeof(IndexBuffer*)/1024);
    fprintf(f,"Term entries total size %dK\n",
	   writer->terms*sizeof(IndexBuffer)/1024);
    fprintf(f,"Strings total size %dK\n",writer->total_string_bytes/1024);
}



int index_buffer_compare(const void *first, const void *next) {
    return strcmp(
	(*(const IndexBuffer **)first)->str,
	(*(const IndexBuffer **)next)->str
	);
}

void index_spool_overflow(IndexWriter *writer) {
    int i,j;
    IndexBuffer *l;
    IndexBuffer **term_array;
    int esize;
    TempFile *temp_file;
    FILE *load_file;
    SgrepData *sgrep=writer->sgrep;

    sgrep_progress(sgrep,"Postings spool overflow. Sorting terms..\n");

    term_array=(IndexBuffer **)sgrep_malloc(sizeof(IndexBuffer *)*writer->terms);
    if (writer->htable) {
	/* Make an array of the hash table */
	j=0;
	for(i=0;i<writer->hash_size;i++) {
	    for(l=writer->htable[i];l;l=l->next) {
		term_array[j++]=l;
	    }
	}
	qsort(term_array,writer->terms,
	      sizeof(IndexBuffer *),index_buffer_compare);
    } else {
	/* Make an array of the sorted buffers */
	j=0;
	for(l=writer->sorted_buffers;l;l=l->next) {
	    assert(j<writer->terms);
	    term_array[j++]=l;
	}
	assert(j==writer->terms);
    }
    temp_file=create_temp_file(sgrep);
    if (!temp_file) {
	sgrep_error(sgrep,"Can't write memory load\n");
	writer->failed=1;
	writer->spool_used=0;
	sgrep_free(term_array);
	return;
    }
    load_file=temp_file_stream(temp_file);    
    for(i=0;i<writer->terms;i++) {
	if ( (i&1023)==0 ) {
	    sgrep_progress(sgrep,"saving memory load: %d/%d entries (%d%%)\r",
			   i,writer->terms,i*100/writer->terms);
	}
	if (term_array[i]->block_used<0) {
	    /* Only write external buffers. First the entry string. */
	    fputs(term_array[i]->str,load_file);
	    fputc(0,load_file);
	    put_int(term_array[i]->list.external.bytes,load_file);
	    /* Then the postings */
	    esize=fwrite_postings(writer,term_array[i],load_file);
	    term_array[i]->saved_bytes+=esize;
	    assert(esize==term_array[i]->list.external.bytes);
	    /* Now empty the entry */
	    term_array[i]->block_used=0;
	}
    }
    sgrep_free(term_array);
    sgrep_progress(sgrep,"\n");
    fflush(load_file);
    if (ferror(load_file)) {
	sgrep_error(sgrep,"Failed to write memory load: %s\n",strerror(errno));
	delete_temp_file(temp_file);
	writer->failed=1;
    } else {
	writer->memory_load_files[writer->memory_loads++]=temp_file; 
    }
    writer->spool_used=0;
}

/* FIXME: Here we assume that sizeof(int) is 4 */
void new_block(IndexWriter *writer,IndexBuffer *buf, unsigned char byte) {
    assert(writer->spool_used<writer->spool_size);
    assert(writer->spool[buf->list.external.current].next==INT_MIN);

    writer->spool[buf->list.external.current].next=writer->spool_used;
    buf->list.external.current=writer->spool_used;
    writer->spool[writer->spool_used].buf[0]=byte;
    writer->spool[writer->spool_used].next=INT_MIN;
    buf->list.external.bytes++;
    buf->block_used=-1;
    writer->spool_used++;
}

void add_byte(IndexWriter *writer,IndexBuffer *buf, unsigned char byte) {
    int used;
    writer->total_postings_bytes++;
    if (buf->block_used>=0) {
	/* Internal block */
	if (buf->block_used<INTERNAL_INDEX_BLOCK_SIZE) {
	    buf->list.internal.ibuf[buf->block_used++]=byte;
	    return;
	}
	/* Does not fit into internal block anymore. Make it external */
	assert(writer->spool_used<writer->spool_size);
	writer->spool[writer->spool_used].next=INT_MIN;
	memcpy(writer->spool[writer->spool_used].buf,
	       buf->list.internal.ibuf,INTERNAL_INDEX_BLOCK_SIZE);
	buf->list.external.first=writer->spool_used;
	buf->list.external.current=writer->spool_used;
	buf->list.external.bytes=buf->block_used;
	buf->block_used=-INTERNAL_INDEX_BLOCK_SIZE;
	writer->spool_used++;
    }
    /* External block */    
    used=-buf->block_used;
    if (used==EXTERNAL_INDEX_BLOCK_SIZE) {
	new_block(writer,buf,byte);
    } else {
	writer->spool[buf->list.external.current].buf[used]=byte;
	buf->block_used--;
	buf->list.external.bytes++;
    }
    assert(writer->spool_used<=writer->spool_size);
    if (writer->spool_used==writer->spool_size) index_spool_overflow(writer);
}

/*
 * Here is the core of the index compression technique: small numbers
 * take less space than large numbers. This function does the actual
 * compression. The mapping of regions (or whateever data is stored
 * under the index term) to small numbers is done elsewhere
 */
#define NEGATIVE_NUMBER_TAG ((unsigned char)255)
#define END_OF_POSTINGS_TAG ((unsigned char)127)
void add_integer(IndexWriter *writer, IndexBuffer *buf, int num) {
    if (num<0) {
	/* Negative number: Add the NEGATIVE_NUMBER tag */
	add_byte(writer,buf,NEGATIVE_NUMBER_TAG);
	/* Add the number as positive integer */
	num=-num;
    }
    if (num<127) {
	/* Eight bits with being 0 */
	/* 01111111 is reserved for end of buffer. Zero is OK */
	add_byte(writer,buf,num);
	writer->entry_lengths[0]++;
    } else if (num<(1<<14)) {
	/* 16 bits with first being 10  */
	add_byte(writer,buf,(num>>8)|128);
	add_byte(writer,buf,num&255);
	writer->entry_lengths[1]++;
    } else if (num<(1<<21)) {
	/* 24 bits with first being 110 */
	add_byte(writer,buf,(num>>16)|(128+64));
	add_byte(writer,buf,(num>>8)&255);
	add_byte(writer,buf,num&255);	 
	writer->entry_lengths[2]++;
    } else if (num<(1<<28)) {
	/* 32 bits with first being 1110 */
	add_byte(writer,buf,(num>>24)|(128+64+32));
	add_byte(writer,buf,(num>>16)&255);
	add_byte(writer,buf,(num>>8)&255);
	add_byte(writer,buf,num&255);
	writer->entry_lengths[3]++;
    } else if (num<=0x7fffffff) {
	/* First byte 11110000*/
	add_byte(writer,buf,0xf0);
	add_byte(writer,buf,(num>>24)&255);
	add_byte(writer,buf,(num>>16)&255);
	add_byte(writer,buf,(num>>8)&255);
	add_byte(writer,buf,num&255);
    } else {
	/* More than 32 bits. Shouldn't happen with ints. */
	sgrep_error(writer->sgrep,"Index value %u is too big!\n",num);
    }
}
    
void add_entry(IndexWriter *writer,IndexBuffer *buf, int index) {
    assert(index>=0);
    index-=buf->last_index;
    buf->last_index+=index;
    add_integer(writer,buf,index);
}

unsigned char get_next_block(IndexWriter *writer,IndexBuffer *buf) {
    assert(buf->block_used<0);
    if (buf->block_used==-EXTERNAL_INDEX_BLOCK_SIZE-1) {
	/* Start scan */
	buf->list.external.current=buf->list.external.first;
    } else {
	/* Next block */
	assert(-buf->block_used==EXTERNAL_INDEX_BLOCK_SIZE);
	assert(writer->spool[buf->list.external.current].next>0);
	buf->list.external.current=writer->spool[buf->list.external.current].next;
    }
    buf->block_used=-1;
    return writer->spool[buf->list.external.current].buf[0];
}


unsigned char get_byte(IndexBuffer *buf) {
    assert(buf->block_used==SHRT_MIN);
    return buf->list.map.buf[buf->list.map.ind++];
#if 0
    if (buf->block_used==SHRT_MIN) {
	return buf->list.map.buf[buf->list.map.ind++];
    }
    if (buf->block_used>=0) {
	assert(buf->block_used<INTERNAL_INDEX_BLOCK_SIZE);
	return buf->list.internal.ibuf[buf->block_used++];
    }
    if (buf->block_used<=-EXTERNAL_INDEX_BLOCK_SIZE) 
	return get_next_block(writer,buf);
    return writer->spool[buf->list.external.current].buf[-(buf->block_used--)];
#endif /* 0 */
}

int get_integer(IndexBuffer *buf) {
    unsigned char i;
    int r;
    int negative=0;

    i=get_byte(buf);
    if (i==NEGATIVE_NUMBER_TAG) {
	negative=1;
	i=get_byte(buf);
    }
    if (i==END_OF_POSTINGS_TAG) {
	/* Found end of index */
	return INT_MAX;
    }
    else if (i<127) r=i; /* 8 bits starting with 0 */
    else if ((i&(128+64))==128) {
	/* 16 bits starting with 10 */
	r=((i&63)<<8)|get_byte(buf);
    }
    else if ((i&(128+64+32))==128+64) {
	/* 24 bits starting with 110 */
	r=(i&31)<<16|(get_byte(buf)<<8);
	r=r|get_byte(buf);
    }
    else if ((i&(128+64+32+16))==128+64+32) {
	/* 32 bits starting with 1110 */
	r=(i&15)<<24|(get_byte(buf)<<16);
	r|=get_byte(buf)<<8;
	r=r|get_byte(buf);      
    } else if(i==0xf0) {
	/* 40 bits starting with 0xf0 */
	r=get_byte(buf)<<24;
	r|=get_byte(buf)<<16;
	r|=get_byte(buf)<<8;
	r|=get_byte(buf);
    } else {
	assert(0 && "Corrupted index file");
	abort();
    }
    return (negative)?-r:r;
}

unsigned int get_entry(IndexBuffer *buf) {
    int r=get_integer(buf);
    if (r==INT_MAX) return r;
    buf->last_index+=r;
    assert(buf->last_index>=0);
    /* fprintf(stderr,"%d\n",buf->last_index); */
    return buf->last_index;
}

static IndexBuffer *new_writer_index_buffer(IndexWriter *writer) {
    struct SgrepStruct *sgrep=writer->sgrep;
    if (writer->free_index_buffers==NULL ||
	writer->first_free_index_buffer==INDEX_BUFFER_ARRAY_SIZE) {
	struct IndexBufferArray *b;
	b=(struct IndexBufferArray *)sgrep_calloc(1,
	    sizeof(struct IndexBufferArray));
	b->next=writer->free_index_buffers;
	writer->first_free_index_buffer=0;
	writer->free_index_buffers=b;
    }
    return &writer->free_index_buffers->bufs[writer->first_free_index_buffer++];    
}

IndexBuffer *find_index_buffer(IndexWriter *writer, const char *str) {
    IndexBuffer **n;
    int h;
    SgrepData *sgrep=writer->sgrep;

    h=hash_function(writer->hash_size,str);

    n=&writer->htable[h];
    while(*n!=NULL) {
	/* There already is entries with same hash value */
	if (strcmp(str,(*n)->str)!=0) {
	    /* No match */
	    n=&(*n)->next;
	} else {
	    /* Found existing entry */
	    return *n;
	}
    }
    writer->terms++;
    if ((writer->terms==writer->hash_size*2)) {
	sgrep_error(sgrep,"Warning: There is more than 2*%d (hash table size) unique index terms.\n",writer->hash_size);
	sgrep_error(sgrep,"Warning: Suggest using larger hash table (-H option).\n");
    }
    *n=new_writer_index_buffer(writer);
    (*n)->str=sgrep_strdup(str);
    (*n)->last_len=strlen(str)-1;
    writer->total_string_bytes+=strlen(str)+1;
    return *n;
}


int read_stop_word_file(IndexWriter *writer, const char *filename) {
    char entry[max_term_len];
    int term_len;
    int ch;
    FILE *stop_file;
    IndexBuffer *ib;
    SGREPDATA(writer);

    stop_file=fopen(filename,"r");
    if (stop_file==NULL) {
	sgrep_error(sgrep,"Failed to read stop word file '%s':%s\n",
		    filename,strerror(errno));
	return SGREP_ERROR;
    }
    
    ch=getc(stop_file);
    while(ch!=EOF) {
	/* If the line starts with a number, ignore them */
	if (ch>='0' && ch<='9') {
	    while(ch>='0' && ch<='9') ch=getc(stop_file);
	    /* And the space, if there was one */
	    if (ch==' ') ch=getc(stop_file);
	}
	
	for(term_len=0;
	    term_len<max_term_len-1 && ch!=EOF && ch!='\n';
	    ch=getc(stop_file)) entry[term_len++]=ch;
	entry[term_len]=0;
	if (term_len>0) {
	    /* fprintf(stderr,"'%s'\n",entry); */
	    ib=find_index_buffer(writer,entry);
	    /* We can't unwind already added postings (because it is not
	     * implemented) so we check that there is none */
	    assert(ib->last_index==0 || ib->last_index==-1);
	    ib->last_index=-1;
	}
	/* Finally, skip the LF */
	if (ch=='\n') ch=getc(stop_file);
    }
    
    fclose(stop_file);
    return SGREP_OK;
}

int add_region_to_index(IndexWriter *writer,
		      const char *str, int start, int end) {
    IndexBuffer *ib;
    int len;
    SGREPDATA(writer);

    
    if (end<start) {
	sgrep_error(sgrep,"BUG: ignoring zero sized region\n");
	return SGREP_OK;
    }
    ib=find_index_buffer(writer,str);

    writer->postings++;
    
    /* Check for stopword */
    if (ib->last_index==-1) return SGREP_OK;

    len=end-start+1;
    /* FIXME: the start!=0 condition should be removed, but removing
     * it needs change in index file format! (In other words: a design
     * bug. Sorry about that. */
    if (ib->last_len==len && start!=0) {
	/* This is the compression hack: skip the end point in entries
	 * having same length */
	if (start==ib->last_index) {
	    /* Bad luck: we have to add zero entry tag. So we duplicate
	     *  it */
	    add_entry(writer,ib,start);
	    add_entry(writer,ib,start);
	} else {
	    add_entry(writer,ib,start);
	}
    } else if (len==-ib->last_len) {
	/* Previous was same lenght as this. Switch to compression hack
	 * state */
	ib->last_len=len;
	add_entry(writer,ib,start);
	add_entry(writer,ib,end);
    } else {	
	/* Lengths did not match. If we we're in compression hack
	 * state, need to add tag to switch state */
	if (ib->last_len>0) {
	    /* Add the zero entry tag to switch state */
	    add_entry(writer,ib,ib->last_index);
	}
	/* Normal entry */
	ib->last_len=-len;
	add_entry(writer,ib,start);
	add_entry(writer,ib,end);
    }
    if (writer->failed) {
	return SGREP_ERROR;
    } else {
	return SGREP_OK;
    }
}

int get_region_index(IndexBuffer *buf, Region *region) {
    int saved_index;
    int s,e;

    saved_index=buf->last_index;
    assert(saved_index!=INT_MAX);
    s=get_entry(buf);
    if (s==INT_MAX) {
	buf->last_index=INT_MAX;
	return 0;
    }

    if (buf->last_len>0) {
	/* We are in compression hack state */
	if (s==saved_index) {
	    /* The zero tag: either switch to normal state or this is
	     * escaped zero tag */
	    s=get_entry(buf);
	    if (s==saved_index && s!=0) {
		/* It was an escaped zero tag */
		region->start=s;
		region->end=s+buf->last_len-1;
		return 1;
	    }
	    /* Switch to normal state. Need to read also end index */
	    e=get_entry(buf);
	    assert(e!=INT_MAX);
	    buf->last_len=0-(e-s+1);
	    region->start=s;
	    region->end=e;
	    return 1;
	}
	/* Ending point was compressed out */
	region->start=s;
	region->end=s+buf->last_len-1;
	return 1;
    }
    /* Normal state. Read also end point */
    e=get_entry(buf);
    assert(e!=INT_MAX);
    if (e-s+1==-buf->last_len) {
	/* Same length twice. Switch to CH state */
	buf->last_len=e-s+1;
    } else {
	/* Different length. Just save the length */
	buf->last_len=0-(e-s+1);
    }
    region->start=s;
    region->end=e;
    return 1;
}

void rewind_index_buffer(IndexBuffer *buf) {
    if (buf->block_used<0) {
	buf->block_used=-EXTERNAL_INDEX_BLOCK_SIZE-1;
    } else {
	buf->block_used=0;
    }
    buf->last_index=0;
}

IndexWriter *new_index_writer(const IndexOptions *options) {
    int i;
    IndexWriter *writer;
    SgrepData *sgrep=options->sgrep;

    writer=sgrep_new(IndexWriter);
    writer->sgrep=options->sgrep;
    writer->options=options;
    writer->file_list=NULL;

    writer->free_index_buffers=NULL;
    writer->first_free_index_buffer=0;
    writer->total_postings_bytes=0;
    writer->terms=0;
    writer->postings=0;
    writer->total_string_bytes=0;
    for(i=0;i<8;i++) writer->entry_lengths[i]=0;

    writer->htable=(IndexBuffer **)sgrep_malloc(
	options->hash_table_size*sizeof(IndexBuffer*));
    /* Mark the hash entries as unused */
    writer->hash_size=options->hash_table_size;
    for(i=0;i<writer->hash_size;i++) writer->htable[i]=NULL;
    writer->spool_size=options->available_memory/
	sizeof(struct IndexBlock);
    writer->spool_used=0;
    writer->spool=(struct IndexBlock*)sgrep_calloc(1,writer->spool_size*sizeof(struct IndexBlock));
    if (writer->spool==NULL) {
	sgrep_error(sgrep,"Could not allocate %dK memory for postings spool\n",
		writer->spool_size*sizeof(struct IndexBlock)/1024);
	sgrep_free(writer->htable);
	sgrep_free(writer);
	return NULL;
    }	
    writer->memory_loads=0;
    writer->stream=NULL;
    writer->failed=0;
    return writer;
}

/*
 * This frees all resources (memory, files, what else?) allocated by
 * IndexWriter. This can be called either because indexing has
 * been successfully completed, or because indexing has failed
 */
void delete_index_writer(IndexWriter *writer) {
    struct IndexBufferArray *b;
    int i;
    SgrepData *sgrep=writer->sgrep;

    /* Close the index file stream */
    if (writer->stream) {
	fclose(writer->stream);
	writer->stream=NULL;
    }
    /* Close all temporary file stream */
    for (i=0;i<writer->memory_loads;i++) {
	if (writer->memory_load_files[i]!=NULL) {
	    delete_temp_file(writer->memory_load_files[i]);
	    writer->memory_load_files[i]=NULL;
	}
    }
    /* Free all the IndexBuffers */
    while (writer->free_index_buffers) {
	while(--writer->first_free_index_buffer>=0) {
	    sgrep_free(writer->free_index_buffers->bufs[writer->first_free_index_buffer].str);
	}
	b=writer->free_index_buffers;
	writer->free_index_buffers=writer->free_index_buffers->next;
	writer->first_free_index_buffer=INDEX_BUFFER_ARRAY_SIZE;
	sgrep_free(b);
    }
    /* Free the postings spool */
    if (writer->spool) {
	sgrep_free(writer->spool);
    }
    /* Free the hash table */
    if (writer->htable) {
	sgrep_free(writer->htable);
    }
    /* Free the writer itself */
    sgrep_free(writer);
}


IndexBuffer *merge_sort_index_buffer(IndexBuffer *list) {
    IndexBuffer *l;
    IndexBuffer *next,*first,*second;
    IndexBuffer *sorted=NULL;

    if (list==NULL) return list;

    /* Split */
    first=NULL;
    second=NULL;
    while(list) {
	next=list->next;
	list->next=first;
	first=list;
	list=next;
	if (list) {
	    next=list->next;
	    list->next=second;
	    second=list;
	    list=next;
	}
    }
    if (second==NULL) return first;

    /* Recursion */
    first=merge_sort_index_buffer(first);
    second=merge_sort_index_buffer(second);

    /* Merge */
    l=NULL;
    while(first&&second) {
	if (first && (!second || strcmp(first->str,second->str)<=0)) {
	    if (l) l=l->next=first;		
	    else l=sorted=first;
	    first=first->next;
	} else {
	    if (l) l=l->next=second;
	    else l=sorted=second;
	    second=second->next;
	}
    }
    assert(first||second);
    if (first) l->next=first;
    else l->next=second;
    
    return sorted;
}

void sort_index_buffers(IndexWriter *writer) {
    IndexBuffer *list;
    IndexBuffer *l,*next;
    IndexBuffer *sorted_buffer;
    int i;
    int state;
    SGREPDATA(writer);

    /* Link buffers from hash table to list */
    list=NULL;
    state=0;
    for(i=0;i<writer->hash_size;i++) {
	for(l=writer->htable[i];l;l=next) {
	    next=l->next;
	    l->next=list;
	    list=l;
	}
    }

    /* Since the hash table is not valid anymore, free it now */
    sgrep_free(writer->htable);

    /* Now sort the buffers */
    sorted_buffer=merge_sort_index_buffer(list);
    writer->htable=NULL;
    writer->sorted_buffers=sorted_buffer;
}

/* There exists a faster algorithm for this, but i don't think that it
 * would give us any noticiable speed advantage in this particular 
 * application, since this isn't the crucial part anyway. */

void count_lcps_recursion(IndexBuffer **array,int len,const char *str) {
    const char *middle_str;
    int middle_ind;
    unsigned int i;
    assert(len!=0);

    middle_ind=len/2;
    middle_str=array[middle_ind]->str;
    for(i=0;str[i]==middle_str[i] && middle_str[i] && str[i]; i++);
    array[middle_ind]->lcp=(i<256)?i:255;
    array[middle_ind]=NULL;

    if (len==1) return;
    if (len==2) {
	count_lcps_recursion(array,1,middle_str);
	return;
    }
    count_lcps_recursion(array,middle_ind,middle_str);
    count_lcps_recursion(array+middle_ind+1,len-middle_ind-1,middle_str);
}

void count_common_prefixes(IndexWriter *writer) {
    int i;
    IndexBuffer *tmp;
    IndexBuffer **sorted_array;
    SGREPDATA(writer);

    sorted_array=(IndexBuffer **)sgrep_malloc(
	writer->terms*sizeof(IndexBuffer *));
    for(tmp=writer->sorted_buffers,i=0;tmp;tmp=tmp->next,i++) {
	assert(i<writer->terms);
	sorted_array[i]=tmp;
    }
    count_lcps_recursion(sorted_array,i,"");
    sgrep_free(sorted_array);
}


void count_statistics(IndexWriter *writer) {
    IndexBuffer *tmp;
    int i;

    writer->strings_lcps_compressed=0;
    for(tmp=writer->sorted_buffers;tmp;tmp=tmp->next) {
	writer->strings_lcps_compressed+=tmp->lcp;
    }

    /* Count the size of file list */
    if (writer->file_list) {
	const char *name;

	writer->flist_size=4; /* Number of files */
	for(i=0;i<flist_files(writer->file_list);i++) {
	    name=flist_name(writer->file_list,i);
	    writer->flist_size+=4;
	    if (name!=NULL) {
		writer->flist_size+=strlen(name)+1;
	    }
	    writer->flist_size+=4;
	}
    } else {
	writer->flist_size=0;
    }

    /*
     * Count the size of index file to be written
     */
    writer->total_index_file_size=1024+
	writer->terms*4+
	writer->total_string_bytes-writer->strings_lcps_compressed+
	writer->terms+
	(writer->total_postings_bytes+writer->terms);
    writer->flist_start=writer->total_index_file_size;
    writer->total_index_file_size+=writer->flist_size;
}

int write_index_term_array(IndexWriter *writer, FILE *stream) {
    int i=0;
    int possible_stop_word_size=0;
    IndexBuffer *tmp=NULL;
    FILE *stop_stream=NULL;
    SGREPDATA(writer);

    for(tmp=writer->sorted_buffers;tmp;tmp=tmp->next) {
        int wbytes;
	/* Index to start of postings for this term */
	put_int(i,stream);

	if (tmp->last_index==-1) {
	    /* This term was a stop word. From now on it is used just like
	     * any other word, except that is has no postings */
	    tmp->last_index=0;
	}
	/* Add the End Of Postings Tag */
	add_byte(writer,tmp,END_OF_POSTINGS_TAG);
	/* Count the length of this terms postings */
	wbytes=
	    strlen(tmp->str)-tmp->lcp+2+
	    tmp->saved_bytes+
	    ((tmp->block_used>=0) ? tmp->block_used : tmp->list.external.bytes);
	i+=wbytes;
	wbytes+=4;

	/* Check for stop word limit */
	if (writer->options->stop_word_limit && 
	    writer->total_index_file_size/wbytes<writer->options->stop_word_limit) {
	    if (possible_stop_word_size==0) {
		sgrep_error(sgrep,"Possible stop words:\n");
	    }
	    sgrep_error(sgrep,"%5dK (%2.2f%%) '%s'\n",wbytes/1024,
			wbytes*100.0/writer->total_index_file_size,tmp->str);
	    possible_stop_word_size+=wbytes;
	}

	/* Check if we should write stop words */
	if (writer->options->output_stop_word_file) {
	    if (stop_stream==NULL) {
		stop_stream=fopen(writer->options->output_stop_word_file,"w+");
		if (stop_stream==NULL) {
		    sgrep_error(sgrep,"Failed to open stop word file '%s':%s\n",
				writer->options->output_stop_word_file,
				strerror(errno));
		    return SGREP_ERROR;
		}
	    }
	    fprintf(stop_stream,"%d %s\n",wbytes,tmp->str);
	}	
    }
    /* Check that stop words we're written without errors */
    if (stop_stream) {
	if (ferror(stop_stream)) {
	    sgrep_error(sgrep,"Failed to write stop word file '%s':%s",
			writer->options->output_stop_word_file,
			strerror(errno));
	    fclose(stop_stream);
	    return SGREP_ERROR;
	}
	fclose(stop_stream);
    }

    /* Total of stop word savings */
    if (possible_stop_word_size>0) {
	    sgrep_error(sgrep,"-------------\n%5dK (%2.2f%%) total\n",
		    possible_stop_word_size/1024,
		    possible_stop_word_size*100.0/writer->total_index_file_size);
    }
    return SGREP_OK;
}    

/*
 * Write the index file header
 */
void write_index_header(IndexWriter *writer) {
    FILE *stream;
    int l=0;
    stream=writer->stream;

    l=fprintf(stream,"%s\n\n%d terms\n%d entries\n",
	      INDEX_VERSION_MAGIC,
	      writer->terms,writer->postings);
    l+=fprintf(stream,"1024 bytes header (%d%%)\n",
	       1024*100/writer->total_index_file_size);
    l+=fprintf(stream,"%d bytes term index (%d%%)\n",
	       writer->terms*4,
	       writer->terms*4*100/writer->total_index_file_size);
    l+=fprintf(stream,"%d bytes strings (%d%%)\n  %d total strings\n  %d compressed with lcps (-%d%%)\n",
	       writer->total_string_bytes-
	              writer->strings_lcps_compressed+writer->terms,
	       (writer->total_string_bytes-writer->strings_lcps_compressed+
		writer->terms)*100/writer->total_index_file_size,
	       writer->total_string_bytes,
	       writer->strings_lcps_compressed-writer->terms,
	       (writer->strings_lcps_compressed-writer->terms)*100/
	             writer->total_string_bytes);
    l+=fprintf(stream,"%d bytes postings (%d%%)\n",
	       writer->total_postings_bytes+writer->terms,
	       (writer->total_postings_bytes+writer->terms)*100/
	             writer->total_index_file_size);
    l+=fprintf(stream,"%d bytes file list (%d%%)\n",
	       writer->flist_size,
	       writer->flist_size*100/writer->total_index_file_size);    
    l+=fprintf(stream,"%d total index size\n--\n",
	       writer->total_index_file_size);
    while(l<512) {
	putc(0,stream);
	l++;
    }

    l+=put_int(writer->terms,stream); /* Number of terms */
    l+=put_int(1024,stream);          /* Starting index of term array */
    l+=put_int(1024+writer->terms*4,stream); /* Starting index of strings and postings */
    l+=put_int(writer->flist_start,stream); /* Starting index of file list */

    while(l<1024) {
	putc(0,stream);
	l++;
    }
}

int write_index_terms(IndexWriter *writer) {
    int total_internal_bytes=0;
    int total_external_bytes=0;
    int total_saved_bytes=0;
    int written_terms=0;
    IndexBuffer *tmp;
    FILE *stream;
    char mlf_string[MAX_MEMORY_LOADS][max_term_len+1];
    int i;
    SGREPDATA(writer);
    FILE *load_stream=NULL;

    /* Rewind the memory load files and find the first string */
    for(i=0;i<writer->memory_loads;i++) {
	int c,j;
	load_stream=temp_file_stream(writer->memory_load_files[i]);

	if (fseek(load_stream,0,SEEK_SET)==EOF) {
	    sgrep_error(sgrep,"Memory load fseek():%s\n",strerror(errno));
	    mlf_string[i][0]=0;
	    return SGREP_ERROR;
	}
	j=0;
	while( (c=getc(load_stream)) && c!=EOF) {
	    mlf_string[i][j++]=c;
	    assert(j<max_term_len);
	}
	if (c==EOF) {
	    sgrep_error(sgrep,"Memory load file #%d truncated!\n",i);
	    return SGREP_ERROR;
	}
	mlf_string[i][j]=0;
	/*fprintf(stderr,"%s\n",mlf_string[i]);*/
    }
    
    stream=writer->stream;
    written_terms=0;
    /* Write the term entries */
    for(tmp=writer->sorted_buffers;tmp;tmp=tmp->next) {

	if ((written_terms&1023)==0 ) {
	    sgrep_progress(sgrep,"Writing index %d/%d entries (%d%%)\r",
			   written_terms,writer->terms,
			   written_terms*100/writer->terms);
	}
	written_terms++;

	putc(tmp->lcp,stream); /* First the lcp */
	fputs(tmp->str+tmp->lcp,stream); /* String with lcp cut off */
	putc(0,stream); /* End of string */


	/* Check the saved memory loads */
	for(i=0;i<writer->memory_loads;i++) {
	    if (strcmp(tmp->str,mlf_string[i])==0) {
		/* Found entry from load file */
		size_t size;
		char buf[8192];
		int c;
		int j;
		load_stream=temp_file_stream(writer->memory_load_files[i]);
		size=getc(load_stream)<<24;
		size|=getc(load_stream)<<16;
		size|=getc(load_stream)<<8;
		size|=getc(load_stream);
		if (feof(load_stream)) {
			sgrep_error(sgrep,"Memory load file truncated?\n");
			return SGREP_ERROR;
		}
		total_saved_bytes+=size;
		/* fprintf(stderr,"ML #%d: '%s' %d bytes\n",i,
			tmp->str,size); */
		while(size>0) {
		    int r;
		    int len=(size<sizeof(buf))?size:sizeof(buf);
		    r=fread(buf,1,len,load_stream);
		    if (r>=0 && r<len) {
			sgrep_error(sgrep,"Memory load file truncated?\n");
			return SGREP_ERROR;
		    }
		    if (r<0) {
			sgrep_error(sgrep,"IO Error when reading memory load:%s\n",
				    strerror(errno));
			return SGREP_ERROR;
		    }
		    fwrite(buf,1,r,stream);
		    size-=r;
		}
		assert(size==0);
		j=0;
		/* fprintf(stderr,"%s\n",mlf_string[i]); */
		while( (c=getc(load_stream)) && c!=EOF) {
		    mlf_string[i][j++]=c;
		    assert(j<=max_term_len);
		}
		mlf_string[i][j]=0;
		if (c==EOF) {
		    /* fprintf(stderr,"Closing ML #%d\n",i); */
		    assert(j==0);
		    delete_temp_file(writer->memory_load_files[i]);
		    writer->memory_load_files[i]=NULL;		    
		}
	    }
	}

	/* Now write the postings from main memory */
	fwrite_postings(writer,tmp,stream);

	/* Count statistics */
	if (tmp->block_used>=0) total_internal_bytes+=tmp->block_used;
	else total_external_bytes+=tmp->list.external.bytes;
	if (ferror(stream)) { 
	    /* The caller will catch the error */
	    sgrep_progress(sgrep,"\n");
	    return SGREP_OK;
	}
    }
    sgrep_progress(sgrep,"\n");
    /* fprintf(stderr,"%d internal, %d external bytes\n",total_internal_bytes,
	    total_external_bytes); */
    assert(total_external_bytes+total_internal_bytes+total_saved_bytes==
	   writer->total_postings_bytes);
    return SGREP_OK;
}

int write_index_file_list(IndexWriter *writer) {
    int i;
    FILE *stream;
    stream=writer->stream;

    if (writer->file_list) {
	const char *name;
	/* Number of files */
	put_int(flist_files(writer->file_list),stream);
	/* Entry for each file */
	for(i=0;i<flist_files(writer->file_list);i++) {
	    name=flist_name(writer->file_list,i);
	    if (name==NULL) {
		put_int(0,stream);
	    } else {
		put_int(strlen(name),stream);
		fputs(name,stream);
		/* remember the trailing zero */
		putc(0,stream);
	    }
	    put_int(flist_length(writer->file_list,i),stream);
	}	
    }
    return SGREP_OK;
}

int write_index(IndexWriter *writer) {
    FILE *stream;
    SGREPDATA(writer);

    stream=writer->stream;
    sort_index_buffers(writer);
    count_common_prefixes(writer);

    count_statistics(writer);
    sgrep_progress(sgrep,"Writing index file of %dK\n",
		   writer->total_index_file_size/1024);

    write_index_header(writer);
    fflush(stream);
    if (ferror(stream)) goto io_error;

    /* Write the term array and count stop words */
    if (write_index_term_array(writer,stream)==SGREP_ERROR) {
	goto error;
    }
    if (ferror(stream)) goto io_error;

    /* Write terms and postigs */
    if (write_index_terms(writer)==SGREP_ERROR) {
	goto error;
    }
    fflush(stream);
    if (ferror(stream)) goto io_error;
    
    /* Now add the file list */
    if (write_index_file_list(writer)==SGREP_ERROR) {
	goto error;
    }
    fflush(stream);
    if (ferror(stream)) goto io_error;

    /* All done */
    return SGREP_OK;

 io_error:
    sgrep_error(sgrep,"IO Error when writing index: %s\n",strerror(errno));
 error:
    sgrep_error(sgrep,"Failed to write index\n");
    return SGREP_ERROR;
}

int create_index(const IndexOptions *options) {
    int i=0;
    IndexWriter *writer=NULL;
    FileList *file_list=NULL;
    SGREPDATA(options);

    file_list=new_flist(sgrep);
    if (options->file_list_files) {
	flist_add_file_list_files(file_list,options->file_list_files);
    }
    if (options->file_list) {
	flist_cat(file_list,options->file_list);
    }
    flist_ready(file_list);
    if (flist_files(file_list)==0) {
	sgrep_error(sgrep,"No files to index.\n");
	goto error;
    }
    writer=new_index_writer(options);
    if (writer==NULL) goto error;
    writer->file_list=file_list;

    /* Check if we have a list of stop words */
    if (writer->options->input_stop_word_file) {
	if (read_stop_word_file(writer,
				writer->options->input_stop_word_file)==SGREP_ERROR) {
	    goto error;
	}
    }

    if (index_search(writer->sgrep,writer,writer->file_list)==SGREP_ERROR) {
	goto error;
    }

    /* index_stream(stdin); */
    /* FIXME: move this "f" thing to pmatch.c */ 
    {
	SgrepString *s=new_string(sgrep,1024);
	for(i=0;i<flist_files(writer->file_list);i++) {
	    string_clear(s);
	    string_cat(s,"f");
	    string_cat(s,flist_name(writer->file_list,i));
	    /* fprintf(stderr,"Adding index file term %s\n",string_to_char(s)); */
	    if (add_region_to_index(writer,
				    string_to_char(s),
				    flist_start(writer->file_list,i),
				    flist_start(writer->file_list,i)+
				    flist_length(writer->file_list,i)-1)
		==SGREP_ERROR) {
		goto error;
	    }
	}
	delete_string(s);
    }


    writer->stream=fopen(writer->options->file_name,"wb");
    if (writer->stream==NULL) {
	sgrep_error(sgrep,"Can't open '%s' for writing:%s\n",
		    writer->options->file_name,strerror(errno));
	goto error;
    }

    if (write_index(writer)==SGREP_ERROR) {
	goto error;
    }

    fclose(writer->stream);
    writer->stream=NULL;

    if (writer->options->index_stats) {
	display_index_statistics(writer);
	sgrep_error(sgrep,"Indexed %d files having %dK total size\n",
		    flist_files(writer->file_list), 
		    flist_total(writer->file_list)/1024);
    }
    
    if (writer->file_list) {
	delete_flist(writer->file_list);
    }
    delete_index_writer(writer);
    return SGREP_OK;

 error:
    if (file_list) {
	delete_flist(file_list);
    }
    if (writer && writer->stream) {
	fclose(writer->stream);
	remove(writer->options->file_name);
    }
    if (writer) delete_index_writer(writer);
    return SGREP_ERROR;
}


/* This recursive binary lookup could probably be done faster.
 * However i'm in a hurry right now, and it's probably not that crucial
 * anyway.
 * 
 * - Looks up index entry region from index file starting form begin
 *   and ending to end.
 * - if end is NULL does an exact lookup with begin
 * - begin=="" and end=="" return all entries
 */
    
int do_recursive_lookup(struct LookupStruct *ls, int s,int e, 
			const char *pstr) {
    const char *str;
    /* Yes, i'd really like to use C++ variable lenght arrays here... */
    char npstr[max_term_len+1];
    int middle=(e-s)/2;
    int rc,lc;

    /* Rebuild current entry */
    str=(const char *)ls->map->entries+get_int(ls->map->array,s+middle);
    if (str[0]>0) {
	assert(pstr!=NULL);
	strncpy(npstr,pstr,str[0]);
    }
    strncpy(npstr+str[0],str+1,max_term_len-str[0]);
    /* puts(npstr);*/

    if (ls->end) {
	int r=0;
	/* Look up a region */
	lc=strncmp(ls->begin,npstr,strlen(ls->begin));
	rc=strncmp(npstr,ls->end,strlen(ls->end));
	
	if (lc<=0 && middle>0) {
	    r+=do_recursive_lookup(ls, s, s+middle, npstr);
	}
	
	if (lc<=0 && rc<=0) {
	    /* Found */
	    r++;
	    ls->callback(npstr,(const unsigned char *)str+2+strlen(str+1),ls);
/*	    printf("'%s': %d: %s\n",npstr,str[0],str+1); */
	}

	if (rc<=0 && s+middle<e-1) {
	    r+=do_recursive_lookup(ls, s+middle+1, e, npstr);
	}
	return r;
    }
    
	/* Lookup exact */
	lc=strcmp(ls->begin,npstr);
	if (lc<0 && middle>0) {
	    return do_recursive_lookup(ls, s, s+middle, npstr);
	} else if (lc>0 && s+middle<e-1) {
	    return do_recursive_lookup(ls, s+middle+1, e, npstr);
	} else if (lc==0) {
	    /* Found */
	    ls->callback(npstr,(const unsigned char *)(str+2+strlen(str+1)),ls);
	    /* printf("'%s': %d: %s\n",npstr,str[0],str+1); */
	    return 1;
	}
	/* Not found */
	return 0;
}

IndexBuffer *new_map_buffer(SgrepData *sgrep,
			    const char *entry,
			    const unsigned char *buf) {
    IndexBuffer *n;
    n=sgrep_new(IndexBuffer);
    n->list.map.buf=buf;
    n->list.map.ind=0;
    n->block_used=SHRT_MIN;
    n->last_index=0;
    n->last_len=strlen(entry)-1;
    n->str=sgrep_strdup(entry);
    n->saved_bytes=-1;
    return n;
}

void delete_map_buffer(SgrepData *sgrep,IndexBuffer *map_buffer) {
    assert(map_buffer->block_used==SHRT_MIN);
    map_buffer->block_used=0;
    sgrep_free(map_buffer->str);
    sgrep_free(map_buffer);
}

void dump_entry(const char *entry, const unsigned char *regions, 
		struct LookupStruct *ls) {
    Region region;
    FILE *f;
    IndexBuffer *map_buffer;
    SGREPDATA(ls);

    f=ls->data.stream;
    map_buffer=new_map_buffer(sgrep,entry,regions);
    fprintf(f,"%s:[",entry);
    while(get_region_index(map_buffer,&region)) {
	fprintf(f,"(%d,%d)",region.start,region.end);
    }
    fprintf(f,"]\n");
    delete_map_buffer(sgrep,map_buffer);
}

void read_unsorted_postings(const char *entry, const unsigned char *regions, 
		   struct LookupStruct *ls) {
    Region r;
    RegionList *list;
    IndexBuffer *map_buffer;
    int size;
    SGREPDATA(ls);
    
    list=ls->data.reader;

    if (LIST_SIZE(list)==0) {
	sgrep_progress(sgrep," reading..");
    }
    size=LIST_SIZE(list);
    map_buffer=new_map_buffer(sgrep,entry,regions);
    
    if (get_region_index(map_buffer,&r)) {
	add_region(list,r.start,r.end);
	while(get_region_index(map_buffer,&r)) {
	    add_region(list,r.start,r.end);
	}
    } else {
	ls->stop_words++;
    }
    delete_map_buffer(sgrep,map_buffer);
    return;
}

Region *merge_regions(SgrepData *sgrep,
		      const int length1, const Region *array1,
		      const int length2, const Region *array2,
		      int *return_length) {
    Region region1,region2;
    Region eor={INT_MAX,INT_MAX};
    int ind1=0;
    int ind2=0;
    int m=0;
    Region *merged;

    /* Initialize */
    merged=(Region *)sgrep_malloc((length1+length2)*sizeof(Region));
    region1=array1[0];
    region2=array2[0];

    /* Do the job */
    while(ind1<length1 || ind2<length2) {
	if (region1.start<region2.start) {
	    /* Region in list 1 is first */
	    merged[m]=region1;
	    region1= (++ind1 < length1) ? array1[ind1] : eor;
	} else if (region1.start>region2.start) {
	    /* Region in list 2 is first */
	    merged[m]=region2;
	    region2= (++ind2 < length2) ? array2[ind2] : eor;
	} else if (region1.end<region2.end) {
	    /* Same start point, region in list 1 is first */
	    merged[m]=region1;
	    region1= (++ind1 < length1) ? array1[ind1] : eor;
	} else if (region1.end==region2.end) {
	    /* Same region in both lists */
	    merged[m]=region1;
	    region1= (++ind1 < length1) ? array1[ind1] : eor;
	    region2= (++ind2 < length2) ? array2[ind2] : eor;
	} else {
	    /* Same start point, region in list 2 is first */
	    merged[m]=region2;
	    region2= (++ind2 < length2) ? array2[ind2] : eor;
	}
	m++;
    }
    assert( m >= ((length1>length2) ? length1:length2));
    *return_length=m;
    return merged;
}

void read_and_sort_postings(const char *entry, const unsigned char *regions, 
			    struct LookupStruct *ls) {
    IndexBuffer *map_buffer;
    struct SortingReaderStruct *read=&ls->data.sorting_reader;
    int i;
    Region first,tmp;
    Region *array;
    int size,length;
    SGREPDATA(ls);

    /* Initialize */
    map_buffer=new_map_buffer(sgrep,entry,regions);
    array=read->saved_array;
    size=read->saved_size;
    length=0;
    first=read->one;

#define ARRAY_PUSH(ARRAY,VALUE,SIZE,LENGTH) do { \
  if ((LENGTH)==(SIZE)) { \
    (SIZE)+=(SIZE)/2; \
    (ARRAY)=(Region *)sgrep_realloc(ARRAY,sizeof(Region)*(SIZE)); \
  }  \
  (ARRAY)[(LENGTH)++]=(VALUE); } while(0)
    
    /* Read */
    while(get_region_index(map_buffer,&tmp)) {
	if (first.start<=tmp.start) {
	    if (first.start<tmp.start || first.end<tmp.end) {
		/* First is before. Add it */
		ARRAY_PUSH(array,first,size,length);
		first.start=INT_MAX;
		read->one.start=INT_MAX;
	    } else {
		assert(first.start==tmp.start);
		if (first.end==tmp.end) {
		    /* Same region, skip first */
		    first.start=INT_MAX;
		    read->one.start=INT_MAX;
		}
	    }
	}
	ARRAY_PUSH(array,tmp,size,length);
    }
    delete_map_buffer(sgrep,map_buffer);
    
    /* Empty entry */
    if (length==0) {
	ls->stop_words++;
	return;
    }
    /* first may sometimes be also last :) */
    if (first.start!=INT_MAX) {
	ARRAY_PUSH(array,first,size,length);
	read->one.start=INT_MAX;
    }
    /* If size==1, we just save the new list */
    if (length==1) {
	read->one=tmp;
	return;
    }
    
    read->saved_array=array;
    read->saved_size=size;

#if 0
    {
	fprintf(stderr,"%6d ",size);
	fprintf(stderr,"merge merged :");
	for(i=0;i<18;i++) {
	    fprintf(stderr,"%7d",1<<i);
	}
	fprintf(stderr,"\n");
	fprintf(stderr,"%6d ",size);
    }
#endif
    
    /* Found first having right size */
    for(i=0; (1<<i)<length ; i++);
    while(read->sizes[i]>0) {
	/* We need to merge */
	Region *merged=NULL;
	int merged_length;
	
	read->lists_merged++;
	read->regions_merged+=length+read->sizes[i];

	merged=merge_regions(sgrep,
			     length,array,
			     read->sizes[i],read->regions[i],
			     &merged_length);

	/* Free the old array(s) */
	if (array!=read->saved_array) {
	    sgrep_free(array);
	    array=NULL;
	}
	sgrep_free(read->regions[i]);

	read->regions[i]=NULL;
	read->sizes[i]=0;

	/* We have new array */
	array=merged;
	length=merged_length;
	if ( (1<<i)<length) i++;	
    }

    if (array==read->saved_array) {
	/* Did not need to merge, but need to copy */
	size_t asize=length*sizeof(Region);
	Region *new_array=(Region *)sgrep_malloc(asize);
	memcpy(new_array,array,asize);	
	array=new_array;
    }

    /* Save the new array */
    read->regions[i]=array;
    read->sizes[i]=length;

    if (i>read->max) read->max=i;
    /*
    fp rintf(stderr,"#%4d %6d :",
	     read->lists_merged,
	     read->regions_merged);
    for(i= 0;i<=read->max;i++) {
	fpr intf(stderr,"%7d",read->sizes[i]);
    }
    fprintf(stderr,"\n");
    */
    while(read->dots<read->regions_merged) {
	sgrep_progress(sgrep,".");
	read->dots+=DOT_REGIONS;
    }
}

int dump_entries(const char *begin, const char *end, 
		 IndexReader *map, FILE *stream) {
    int hits;
    struct LookupStruct ls;
    SGREPDATA(map);

    ls.sgrep=sgrep;
    ls.begin=begin;
    ls.end=end;
    ls.map=map;
    ls.callback=dump_entry;
    ls.data.stream=stream;

    hits=do_recursive_lookup(&ls,0,map->len,"");
    sgrep_error(sgrep,"%d entries\n",hits);
    return hits;
}

IndexReader *new_index_reader(SgrepData *sgrep,const char *filename) {
    IndexReader *imap;
    const unsigned char *ptr;

    imap=sgrep_new(IndexReader);
    imap->sgrep=sgrep;
    imap->filename=filename;
    imap->size=map_file(sgrep,filename,&imap->map);
    if (imap->size==0) goto error;
    if (imap->size<=1024) {
	sgrep_error(sgrep,"Too short index file '%s'",filename);
	goto error;	
    }
    
    ptr=(const unsigned char *)imap->map;
    if (strncmp((const char *)ptr,INDEX_VERSION_MAGIC,
		strlen(INDEX_VERSION_MAGIC))!=0) {
	sgrep_error(sgrep,"File '%s' is not an sgrep index.\n",filename);
	goto error;
    }
    ptr+=512;
    imap->len=get_int(ptr,0);
    imap->array=((const unsigned char*)imap->map)+get_int(ptr,1);
    imap->entries=((const char *)imap->map)+get_int(ptr,2);
	    

    sgrep_progress(sgrep,"Using index '%s' of %dK size containing %d terms\n",
		   imap->filename,imap->size/1024,imap->len);
    return imap;

 error:
    if (imap->map) unmap_file(sgrep,imap->map,imap->size);
    sgrep_free(imap);
    return NULL;
}

FileList *index_file_list(IndexReader *imap) {
    int file_list_start;
    SGREPDATA(imap);

    file_list_start=get_int(((const unsigned char *)imap->map)+512,3);
    /* Check and read file list */
    if (file_list_start) {
	/* Index contains a file list */
	const unsigned char *flist_ptr;
	int files;
	int i;
	int l;
	int size;
	const char *name;
	FileList *file_list;

	file_list=new_flist(sgrep);
	flist_ptr=((const unsigned char *)imap->map)+file_list_start;

	files=get_int(flist_ptr,0);
 	/* fprintf(stderr,"%d files\n",files); */
	for(i=0;i<files;i++) {
	    flist_ptr+=4;
	    l=get_int(flist_ptr,0);
	    flist_ptr+=4;
	    name=(const char *)flist_ptr;
	    flist_ptr+=l+1;
	    size=get_int(flist_ptr,0);
	    /* fprintf(stderr,"%d %s %d\n",l,name,size); */
	    flist_add_known(file_list,name,size);
	}
	flist_ready(file_list);
	return file_list;
    } else return NULL;

}

void delete_index_reader(IndexReader *reader) {
    SGREPDATA(reader);
    unmap_file(sgrep,reader->map,reader->size);
    sgrep_free(reader);
}


void set_default_index_options(SgrepData *sgrep,IndexOptions *o) {
    *o=default_index_options;
    o->sgrep=sgrep;
}

/*
 * This lookup version is faster (though uses more memory), 
 * if it possible to have multiple hits with one term
 */
RegionList *index_lookup_sorting(IndexReader *map, const char *term,
				 struct LookupStruct *ls,
				 int *return_hits) {    
    struct SortingReaderStruct *reader=&ls->data.sorting_reader;
    Region *current;
    int len;
    RegionList *result;
    int i;
    SGREPDATA(map);    

    /* Initialize our private part of LookupStruct */
    ls->callback=read_and_sort_postings;
    reader->max=0;
    reader->regions_merged=0;
    reader->lists_merged=0;
    reader->one.start=
	reader->one.end=INT_MAX;
    memset(&reader->sizes,0,sizeof(reader->sizes));
    memset(&reader->regions,0,sizeof(reader->regions));
    reader->saved_size=LIST_NODE_SIZE;
    reader->saved_array=(Region *)sgrep_malloc(
	sizeof(Region)*reader->saved_size);
    reader->dots=0;
    
    /* Do the lookup */
    *return_hits=do_recursive_lookup(ls,0,map->len,"");

    sgrep_free(reader->saved_array);

    /* Check for the one region "array" */
    if (reader->one.start!=INT_MAX) {
	current=sgrep_new(Region);
	current[0]=reader->one;
	len=1;
    } else {
	current=NULL;
	len=0;
    }

    /* Do the final merge */
    /* sgrep_progress(sgrep,"\nFinal merge"); */
    
    for(i=0;i<=reader->max;i++) {
	if (reader->sizes[i]) {
	    if (current) {
		Region *new_current;
		/* sgrep_progress(sgrep,":(%d+%d)",len,reader->sizes[i]); */
		reader->lists_merged++;
		reader->regions_merged+=len+reader->sizes[i];
		new_current=merge_regions(sgrep,
					  len,current,
					  reader->sizes[i],reader->regions[i],
					  &len);
		sgrep_free(current);
		sgrep_free(reader->regions[i]);
		current=new_current;
		while(reader->dots<reader->regions_merged) {
		    sgrep_progress(sgrep,".");
		    reader->dots+=DOT_REGIONS;
		}
	    } else {
		current=reader->regions[i];
		len=reader->sizes[i];
	    }
	}
    }

    /* FIXME: This loop could be avoided. */
    result=new_region_list(sgrep);
    result->nested=1;
    reader->lists_merged++;
    reader->regions_merged+=len;
    /* sgrep_progress(sgrep,"\nCreating region list.."); */
    for(i=0;i<len;i++) {
	add_region(result,current[i].start,current[i].end);
    }
    if (current) sgrep_free(current);

    /* sgrep_progress(sgrep,"\n Total merges:%d regions merged %d\n",
       reader->lists_merged,reader->regions_merged); */
    
    return result;
}

/*
 * This lookup version is faster with one term, but uses less memory
 * in every case
 */
RegionList *index_lookup(IndexReader *map,const char *term) {
    int hits;
    struct LookupStruct ls;
    RegionList *l;
    SGREPDATA(map);

    /* Initialize LookupStruct */
    ls.sgrep=sgrep;
    ls.map=map;
    ls.stop_words=0;

    if (sgrep->progress_output) {
	SgrepString *s=new_string(sgrep,max_term_len);
	string_cat_escaped(s,term);
	sgrep_progress(sgrep,"Looking up '%s'..",string_to_char(s));
	delete_string(s);
    }

    if (term[strlen(term)-1]=='*') {
	char *tmp=NULL;
	tmp=sgrep_strdup(term);
	tmp[strlen(tmp)-1]=0;
	ls.begin=ls.end=tmp;

#if 1 /* USE_SORTING_INDEX_READER */
	l=index_lookup_sorting(map,term,&ls,&hits);
#else
	l=new_region_list(sgrep);
	list_set_sorted(l,NOT_SORTED);
	l->nested=1;

	ls.data.reader=l;
	ls.callback=read_unsorted_postings;
	
	/* Do the lookup */
	hits=do_recursive_lookup(&ls,0,map->len,"");
#endif
	/* Clean up */
	sgrep_free(tmp);
	ls.begin=NULL;
	ls.end=NULL;
    } else {
	l=new_region_list(sgrep);
	if (term[0]=='@') {
	    l->nested=1;
	} else {
	    l->nested=0;
	}
	ls.data.reader=l;
	ls.begin=term;
	ls.end=NULL;
	ls.callback=read_unsorted_postings;
	/* Do the lookup */	
	hits=do_recursive_lookup(&ls,0,map->len,"");
    }

    /* Report progress */
    if (LIST_SIZE(l)>0) {
	if (ls.stop_words==0) {
	    sgrep_progress(sgrep," %d/%d hits/postings found.",
		    hits,LIST_SIZE(l));
	} else {
	    sgrep_progress(sgrep," %d/%d hits/postings (%d stopwords) found.",
		    hits,LIST_SIZE(l),ls.stop_words);
	}
    } else {
	if (ls.stop_words==0) {
	    sgrep_progress(sgrep," not found.");
	} else {
	    sgrep_progress(sgrep," stopword.");
	}
    }	

    /* Do the sorting if necessary */
    if (hits>1 && l->sorted!=START_SORTED) {
	sgrep_progress(sgrep," sorting..");
	remove_duplicates(l);
	sgrep_progress(sgrep," done.");
    } else {
	list_set_sorted(l,START_SORTED);
    }
    
    /* All done */
    sgrep_progress(sgrep,"\n");
    return l;
}

void add_to_entry_list(const char *entry, const unsigned char *regions,
		       struct LookupStruct *ls) {
    struct IndexEntryStruct *n;
    IndexEntryList *list=ls->data.entry_list;
    SGREPDATA(ls);

    n=sgrep_new(IndexEntry);
    n->term=sgrep_strdup(entry);
    n->postings=regions;
    n->next=NULL;
    if (list->last) {
	list->last->next=n;
    } else {
	list->first=n;
    }
    list->last=n;
}

IndexEntryList *index_term_lookup(IndexReader *reader,
				  const char *first_prefix,
				  const char *last_prefix) {
    IndexEntryList *n;
    struct LookupStruct ls;
    SGREPDATA(reader);

    ls.sgrep=sgrep;
    assert(reader!=NULL && first_prefix!=NULL && 
	   (last_prefix==NULL || strcmp(first_prefix,last_prefix)<=0));

    n=sgrep_new(IndexEntryList);
    n->reader=reader;
    n->first=NULL;
    n->last=NULL;

    ls.begin=first_prefix;
    ls.end=last_prefix;
    ls.map=reader;
    ls.callback=add_to_entry_list;
    ls.data.entry_list=n;

    n->hits=do_recursive_lookup(&ls,0,reader->len,"");

    return n;
}
IndexEntry *index_first_entry(IndexEntryList *l) {
    return l->first;
}
IndexEntry *index_next_entry(IndexEntry *e) {
    return e->next;
}
const char *index_entry_term(IndexEntry *e) {
    return e->term;
}

int index_list_size(IndexEntryList *l) {
    return l->hits;
}

void delete_index_entry_list(IndexEntryList *l) {
    IndexEntry *e,*t;
    SGREPDATA(l->reader);
    e=l->first;
    while(e!=NULL) {
	t=e;
	e=e->next;
	sgrep_free(t->term);
	sgrep_free(t);
    }
    l->first=NULL;
    l->last=NULL;
    l->hits=-1;
    sgrep_free(l);
}

int index_query(IndexOptions *options, int argc, char *argv[]) {
    IndexReader *reader;
    SGREPDATA(options);

    reader=new_index_reader(sgrep,sgrep->index_file);
    if (reader==NULL) {
	sgrep_error(sgrep,"No index to query. Bailing out\n");
	goto error;
    }

    switch (options->index_mode) {
    case IM_TERMS: {
	IndexEntryList *list;
	IndexEntry *entry;
	SgrepString *tmp;

	if (argc==0 || argc>2) {
	    sgrep_error(sgrep,"Usage -x index -q terms start_term [end_term]\n");
	    goto error;
	}
	list=index_term_lookup(reader,argv[0],argv[1]);	
	if (!list) goto error;	    

	tmp=new_string(sgrep,max_term_len);
	entry=index_first_entry(list);
	while(entry) {
	    string_clear(tmp);
	    string_cat_escaped(tmp,index_entry_term(entry));
	    printf("%s\n",string_to_char(tmp));
	    entry=index_next_entry(entry);
	}		   
	delete_index_entry_list(list);
	delete_string(tmp);
	break;
    }
    default:
	sgrep_error(sgrep,"index_query: got unknown index mode %d\n",
		    options->index_mode);
	goto error;
    }

    if (reader) delete_index_reader(reader);
    return SGREP_OK;

 error:
    if (reader) delete_index_reader(reader);
    return SGREP_ERROR;
}



#if 0
/* This was used for testing and debugging */
void dump_index() {
    int count,s,e;
    IndexBuffer *sorted=NULL;

    assert(0);

    while(sorted!=NULL) {
	printf("%d:%s:%d:[",sorted->lcp,sorted->str,
	    (sorted->block_used>=0) ? sorted->block_used:
	       sorted->list.external.bytes );
	rewind_index_buffer(sorted);
	count=0;
	while(get_region_index(sorted,&s,&e)) {
	    printf("(%d,%d)",s,e); fflush(stdout);
	    count++;
	}
	printf("]:%d\n",count);
	sorted=sorted->next;
    }
    printf("Total lcps %d(%dK) being %d%% of %dK strings\n",
	   writer->strings_lcps_compressed,writer->strings_lcps_compressed/1024,
	   writer->strings_lcps_compressed*100/writer->total_string_bytes,
	   total_string_size/1024);
}
#endif /* 0 */
