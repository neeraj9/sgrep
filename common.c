/*
	System: Structured text retrieval tool sgrep.
	Module: common.c
	Author: Pekka Kilpeläinen & Jani Jaakkola
	Description: common functions used by other modules
	Version history: Original version February 1995 by JJ & PK
	Copyright: University of Helsinki, Dept. of Computer Science
*/

#include <stdarg.h>
#include <string.h>
#include <errno.h>
#include <ctype.h>

#define SGREP_LIBRARY
#include "sgrep.h"


ListNode *get_start_sorted_list(RegionList *s);
ListNode *get_end_sorted_list(RegionList *s);

/*
 * Moved to here from main.c: FIXME: maybe own module for these.
 */

ParseTreeNode *parse_and_optimize(SgrepData *sgrep,const char *query,
				     struct PHRASE_NODE **phrases) {
    
    ParseTreeNode *root;
    /*
     * Optimize the operator tree 
     */
    root=parse_string(sgrep,query,phrases);
    if (root==NULL) {
	/* Parse error (probably) */
	return NULL;
    }

#ifdef DEBUG
    fprintf(stderr,"Optimizing operator tree\n");
#endif
    optimize_tree(sgrep,&root,phrases);

    if (sgrep->do_concat)
    {
	/* If we do concat on result list, we add a concat operation to
	 * parse tree */
	ParseTreeNode *concat=sgrep_new(ParseTreeNode);
	concat->oper=CONCAT;
	concat->left=root;
	concat->right=NULL;
	concat->leaf=NULL;
	concat->parent=NULL;
	concat->refcount=1;
	concat->result=NULL;
	root=concat;
    };
    return root;
}

/*
 * Functions for handling non null terminated strings 
 * non null terminating strings won't work in version 2.0
 * (maybe never)
 */
SgrepString *new_string(SgrepData *sgrep,size_t size)
{
	SgrepString *s;
	
	s=sgrep_new(SgrepString);
	s->sgrep=sgrep;
	s->s=(char *)sgrep_malloc(size+1);
	s->size=size;
	s->length=0;
	s->s[0]=0;
	s->escaped=NULL;
	return s;
}

void delete_string(SgrepString *s) {
    SGREPDATA(s);
    sgrep_free(s->s);
    if (s->escaped) {
	delete_string(s->escaped);
    }
    sgrep_free(s);
}

SgrepString *init_string(SgrepData *sgrep, size_t size, const char *src)
{
	SgrepString *s;
	
	s=new_string(sgrep,size);
	memcpy(s->s,src,size);
	s->s[size]=0;
	s->length=size;
	return s;
}

void string_cat_escaped(SgrepString *escaped, const char *str) {
    int i;
    int c;

    for(i=0;str[i];i++) {
	c=(unsigned char)str[i];
	switch(c) {
	case '\n':
	    string_cat(escaped,"\\n");
	    break;
	case '\r':
	    string_cat(escaped,"\\r");
	    break;
	case '\b':
	    string_cat(escaped,"\\b");
	    break;
	case '"':
	    string_cat(escaped,"\\\"");
	    break;
	case 255: {
	    /* Encoded character */
	    int ch=0;
	    char buf[40];
	    int x=0;
	    i++;
	    c=(unsigned char)str[i];
	    while(c && c!=32) {
		ch|=(c-33) << x;
		x+=6;
		i++;
		c=(unsigned char)str[i];
	    }
	    if (c==0) {
		sgrep_error(escaped->sgrep,
			    "Could not decode internal encoded character!\n");
	    } else {
		sprintf(buf,"\\#x%x;",ch);
		string_cat(escaped,buf);
	    }
	    break;
	}
	default:
	    if (c<32) {
		char buf[30];
		sprintf(buf,"\\#x%x;",c);
		string_cat(escaped,buf);
	    } else {
		string_push(escaped,c);
	    }
	    break;
	}
    }
}

const char *string_escaped(SgrepString *str) {    
    if (!str->escaped) {
	str->escaped=new_string(str->sgrep,str->length+8);
    } else {
	string_clear(str->escaped);
    }
    string_cat_escaped(str->escaped,string_to_char(str));
    return string_to_char(str->escaped);
}

void push_front(SgrepString *s,const char *str) {
    char *tmp;
    int l;
    SGREPDATA(s);

    l=strlen(str);
    tmp=(char *)sgrep_malloc(s->length+l+1);
    memcpy(tmp,str,l);
    memcpy(tmp+l,s->s,s->length);
    sgrep_free(s->s);
    s->s=tmp;
    s->length+=l;
    s->s[s->length]=0;
    s->size=s->length+1;
}

void string_cat(SgrepString *s, const char *str) {
    int l;
    SGREPDATA(s);

    l=strlen(str);
    if (s->length+l+1>=s->size) {
	s->size=s->length+l+1;
	s->s=(char *)sgrep_realloc(s->s,s->size);	
    }
    memcpy(s->s+s->length,str,l);
    s->length+=l;
    s->s[s->length]=0;
}

void real_string_push(SgrepString *s, SgrepChar ch) {
    SGREPDATA(s);

    if (s->length+1>=s->size) {	
	s->size=(s->size<16) ? 32 : s->size+s->size/2;	
	s->s=(char *)sgrep_realloc(s->s,s->size);
    }
    if (ch>254) {
	((unsigned char *)s->s)[s->length++]=255;
	while(ch>0) {
	    string_push(s,(ch%64)+33);
	    ch=ch/64;
	}
	string_push(s,32);
    } else {
	s->s[s->length++]=ch;
    }
}

void string_tolower(SgrepString *s, int from) {
    unsigned int i=from;
    while(i<s->length) {
	if ((unsigned char)s->s[i]==255) {
	    /* Just ignore chars >255 */
	    i++;
	    while(i<s->length && s->s[i]!=32) i++;
	} else {
	    s->s[i]=tolower(s->s[i]);
	}
	i++;
    }
}

void string_toupper(SgrepString *s, int from) {
    unsigned int i=from;
    while(i<s->length) {
	if ((unsigned char)s->s[i]==255) {
	    /* Just ignore chars >255 */
	    i++;
	    while(i<s->length && s->s[i]!=32) i++;
	} else {
	    s->s[i]=toupper(s->s[i]);
	}
	i++;
    }
}

int sgrep_error(SgrepData *sgrep,char *format, ...) {
    char tmpstr[2048];
    int l;
    va_list ap;

    if (!sgrep) return 0;
    va_start(ap,format);
#if HAVE_VSNPRINTF
    l=vsnprintf(tmpstr,sizeof(tmpstr),format,ap);
#else
    l=vsprintf(tmpstr,format,ap);
#endif
    va_end(ap);
    if (sgrep->error_stream) {
	fputs(tmpstr,sgrep->error_stream);
    } else {
	if (sgrep->error) {
	    string_cat(sgrep->error,tmpstr);
	} else {
	    sgrep->error=init_string(sgrep,l,tmpstr);
	}
    }
    return l;
}

int sgrep_progress(SgrepData *sgrep,char *format, ...) {
    va_list ap;
    int l=0;
    
    if (!sgrep) return 0;
    va_start(ap,format);
    if (sgrep->progress_output) {
	l=vfprintf(sgrep->progress_stream,format,ap);
	fflush(sgrep->progress_stream);
    }
    va_end(ap);
    return l;
}


/*
 * Data structure representing a list of input files
 */
typedef struct {
    int start;	/* Start index of a file */
    int length;	/* Length of a file */
    char *name;	/* Name of the file, NULL if stdin */
} OneFile;
struct FileListStruct {
    SgrepData *sgrep;
    int total_size;   /* Total length of all files in bytes */
    int num_files;    /* How many files */
    int allocated;    /* How many OneFile entries allocated */
    OneFile *files;   /* Since this list must be binary searchable, files
		       * are kept in array instead of linked list */
    int last_errno;   /* Remember the last error in add() */
    int progress_limit; /* When to show progress */
};

int flist_last_errno(const FileList *list) {
    return list->last_errno;
}

/*
 * FileList handling routines 
 */
FileList *new_flist(SgrepData *sgrep) {
    FileList *ifs;

    ifs=sgrep_new(FileList);
    ifs->progress_limit=100;
    ifs->sgrep=sgrep;
    ifs->allocated=256; /* arbitrary */
    ifs->files=(OneFile *) 
	sgrep_malloc( sizeof(OneFile) * ifs->allocated );
    ifs->num_files=0;
    ifs->total_size=0;
    ifs->last_errno=0;
    return ifs;
}

/*
 * Adds a file to filelist *
 */

void flist_add_known(FileList *ifs, const char *name, int length) {
    SGREPDATA(ifs);
    if (ifs->num_files>=ifs->allocated) {
	ifs->files=(OneFile *)
	    sgrep_realloc(ifs->files,sizeof(OneFile)*ifs->allocated*2);
	ifs->allocated*=2;
    }
    ifs->files[ifs->num_files].start=ifs->total_size;
    ifs->files[ifs->num_files].length=length;
    ifs->files[ifs->num_files].name=(name) ? sgrep_strdup(name):NULL;
    ifs->total_size+=length;
    ifs->num_files++;
}

FileList *flist_duplicate(FileList *list) {
    FileList *copy=new_flist(list->sgrep);
    flist_cat(copy,list);
    return copy;
}

void flist_cat(FileList *to, FileList *from) {
    int i;
    for(i=0;i<flist_files(from);i++) {
	flist_add_known(to,flist_name(from,i),flist_length(from,i));
    }
}

int flist_exists(FileList *list, const char *name) {
    int i;
    for(i=0;i<flist_files(list);i++) {
	if (strcmp(name,flist_name(list,i))==0) return 1;
    }
    return 0;
}

/*
 * Checks that given file really exist and is usable to sgrep
 * If it is, adds it to FileList.
 * Returns SGREP_ERROR or SGREP_OK
 */
int flist_add(FileList *ifs, const char *name) {
    FILE *fd=NULL;
    int ls=0;
    SGREPDATA(ifs);
    TempFile *temp=NULL;
    
    /* Filelist checking may take it's time */
    if (ifs->progress_limit) {
	if (flist_files(ifs)+1==ifs->progress_limit) {
	    sgrep_progress(sgrep,"Checking files.");
	} else if ( (flist_files(ifs)+1)%ifs->progress_limit==0) {
	    sgrep_progress(sgrep,".");
	}
    }

    if (strcmp(name,"-")==0)
    {
	/* We try to read stdin */
	/* FIXME: warn when stdin is used while indexing! */
	temp=temp_file_read_stdin(sgrep);
	if (temp==NULL) return SGREP_ERROR;
	fd=temp_file_stream(temp);
    } else {
	fd=fopen(name,"rb");
	if (!fd) {
	    sgrep_error(sgrep,"open '%s': %s\n",name,strerror(errno));
	    return SGREP_ERROR;
	}
    }

    /* We do sgrep only on files which we can open, read and lseek */
    if (
	fseek(fd,0,SEEK_END)<0 ||
	(ls=ftell(fd))<0 ||
	(fgetc(fd) && 0) ||
	ferror(fd)
	) {
	sgrep_error(sgrep,"File '%s': %s\n",name,strerror(errno));
	ifs->last_errno=errno;
	if (fd && (!temp)) fclose(fd);
	return SGREP_ERROR;
    }
    if (fd && (!temp)) fclose(fd);
    if (ls==0) {
	sgrep_error(sgrep,"Ignoring zero sized file '%s'\n",name);
	return SGREP_ERROR;
    }
    /* Found a valid file */
    /* sgrep_progress(sgrep,"file '%s' start=%d len=%d\n",
       name,ifs->total_size,ls); */

    if (temp) {
	flist_add_known(ifs,temp_file_name(temp),ls);
    } else {
	flist_add_known(ifs,name,ls);
    }
    return SGREP_OK;
}

int flist_path_is_absolute(FileList *list, const char *name) {
#if HAVE_UNIX
    return name[0]=='/';
#elif HAVE_WIN32
    if (name[0]=='\\') return 1;
    if (isalpha(name[0]) && name[1]==':') return 1;
    return 0;
#else
#error "Needs flist_path_is_absolute implementation"    
#endif
}

SgrepString *flist_get_path(FileList *list, const char *name) {
    SGREPDATA(list);
    int len;
    int i;
#if HAVE_UNIX
    len=strlen(name);
    for(i=len-1;i>=0;i--) {
	if (name[i]=='/') {
	    return init_string(sgrep,i+1,name);
	}
    }
    return new_string(sgrep,30);
#elif HAVE_WIN32
    len=strlen(name);
    for(i=len-1;i>=0;i--) {
	if (name[i]=='/' || name[i]=='\\') {
	    return init_string(sgrep,i+1,name);
	}
	if (name[i]==':' && i==1 && isalpha(name[0])) {
	    return init_string(sgrep,i+1,name);
	}
    }
    return new_string(sgrep,30);
#else
#error "Needs flist_path_is_absolute implementation"    
#endif	
}

int flist_add_relative(FileList *list, int relative_to, const char *name) {
    SgrepString *path;
    int r;
    assert(relative_to>=0 && relative_to<flist_files(list));
    if (flist_path_is_absolute(list,name)) {
	return flist_add(list,name);
    }
    path=flist_get_path(list,flist_name(list,relative_to));
    string_cat(path,name);
    r=flist_add(list,path->s);
    delete_string(path);
    return r;
}

void delete_flist(FileList *list) {
    int i;
    SGREPDATA(list);

    for(i=0;i<flist_files(list);i++) {
	if (list->files[i].name!=NULL) {
	    sgrep_free(list->files[i].name);
	    list->files[i].name=NULL;
	}
    }		   
    sgrep_free(list->files);
    list->files=NULL;
    sgrep_free(list);
}

void flist_ready(FileList *ifs) {
    SGREPDATA(ifs);

    if (ifs->num_files==0) {
	ifs->allocated=1;
    } else {
	ifs->allocated=ifs->num_files;
    }
    ifs->files=(OneFile *)sgrep_realloc(ifs->files,ifs->allocated*sizeof(OneFile));
    if (ifs->progress_limit && ifs->num_files>=ifs->progress_limit) {
	sgrep_progress(sgrep," done.\n");
    }
    ifs->progress_limit=0;
}

const char *flist_name(const FileList *list, int n) {
    if (n<0 || n>=list->num_files) return NULL;
    return list->files[n].name;
}

int flist_length(const FileList *list, int n) {
    if (n<0 || n>=list->num_files) return SGREP_ERROR;
    return list->files[n].length;
}
int flist_start(const FileList *list, int n) {
    if (n<0 || n>=list->num_files) return SGREP_ERROR;
    return list->files[n].start;
}

int flist_total(const FileList *list) {
    return list->total_size;
}
int flist_files(const FileList *list) {
    return list->num_files;
}

/*
 * Finds out a file num where a given region start poit 
 * resides using binary search 
 * returns -1 if region is outside file list 
 */
int flist_search(const FileList *output_files, int s)
{
	int bs,be,bm;

	int rounds=0;
	assert(output_files && output_files->num_files>0);
	if (s>flist_total(output_files)-1) return -1;
	if (output_files->num_files==1) return 0;
	
	bs=0;be=output_files->num_files;
	bm=(bs+be)/2;
	while ( output_files->files[bm].start>s || 
		output_files->files[bm].start+output_files->files[bm].length<=s )
	{
		if (output_files->files[bm].start>s) be=bm;
		else bs=bm+1;
		bm=(bs+be)/2;
		/* Stupid trick to catch infinite loops */
		assert(++rounds<1000); 
	}
	return bm;
}

int flist_add_one_file_list_file(FileList *ifs, const char *filename) {
    FILE *file_list_stream;
    char name_buf[1024];
    int c;
    SGREPDATA(ifs);
    int line;

    file_list_stream=fopen(filename,"r");
    if (file_list_stream==NULL) {
	sgrep_error(sgrep,"open '%s':%s\n",filename,
		    strerror(errno)); 
	return SGREP_ERROR;
    }

    
    do {
	size_t i=0;
	line=1;
	/* Read a line */
	while( (c=getc(file_list_stream))!='\n' && c!=EOF && 
	       i<(sizeof(name_buf)-1)) {
	    name_buf[i++]=c;
	}
	if (i==(sizeof(name_buf)-1)) {
	    sgrep_error(sgrep,"File name too long in %s:%d\n",
			filename,line);
	    while(c!='\n' && c!=EOF) c=getc(file_list_stream);
	}
	if (i>0) {
	    name_buf[i]=0;
	    flist_add(ifs,name_buf);
	}
	line++;
    } while(c!=EOF);

    fclose(file_list_stream);
    file_list_stream=NULL;
    return SGREP_OK;
}

int flist_add_file_list_files(FileList *ifs, FileList *file_lists) {
    int i;
    for(i=0;i<flist_files(file_lists);i++) {
	flist_add_one_file_list_file(ifs,flist_name(file_lists,i));
    }
    return SGREP_OK;
}


FileList *check_files(SgrepData *sgrep, int argc, char *argv[],
		      int num_file_list_files,
		      char *file_list_files[])
{
    FileList *ifs;
    int fnum,anum;
    char *tmparg[]={"-",NULL};

    ifs=new_flist(sgrep);

    if (argc==0 && num_file_list_files==0) {
	/* Use stdin when nothing else is given */
	argc=1;
	argv=tmparg;
    }

    /* Check for files given with -F option */
    for (fnum=0;fnum<num_file_list_files;fnum++) {
	flist_add_one_file_list_file(ifs,file_list_files[fnum]);
    }

    /* Check for files given in command line */
    for(anum=0;anum<argc;anum++) {
	/* fprintf(stderr,"Adding %s\n",argv[anum]); */
	flist_add(ifs,argv[anum]);
#if DO_GLOB
	{
	    xxx /* Does not work */
	    glob_t globbuf;
	    char *tmp;
	    int e,i;
	    e=glob(name, 0, NULL, &globbuf);
	    for(i=0;e==0 && i<globbuf.gl_pathc;i++) {
		tmp=strdup(globbuf.gl_pathv[i]);
		if (!check_one_file(tmp,ifs)) {
		    free(tmp);
		}		
	    }
	    globfree(&globbuf);
	    free(name);
	}
#endif /* DO_GLOB */
    }
    flist_ready(ifs);
    if (flist_files(ifs)>=ifs->progress_limit) {
	sgrep_progress(sgrep," done.\n");
    }
    ifs->progress_limit=0;

    /*  
     * update statistics
     */
    stats.input_size+=flist_total(ifs);
    return ifs;
}


/*
 * Allocates a new GC_NODE
 */
ListNode *new_list_node(SgrepData *sgrep)
{
    ListNode *n;
    stats.gc_nodes++;
    stats.gc_nodes_allocated++;
    n=sgrep_new(ListNode);
    n->prev=NULL;
    n->next=NULL;
    return n;
}

/*
 * Inserts new ListNode to RegionList
 */
void insert_list_node(RegionList *l) {
    ListNode *new_node;
    assert(l->length==LIST_NODE_SIZE);
    new_node=new_list_node(l->sgrep);
    l->last->next=new_node;
    new_node->prev=l->last;
    l->last=new_node;
    l->length=0;
    l->nodes++;
}




/*
 * initializes a gc list 
 */
void init_region_list(RegionList *l)
{
      l->first=new_list_node(l->sgrep);
      l->last=l->first;
      l->last->next=NULL;
      l->last->prev=NULL;
      l->length=0;
      l->nodes=1;
      l->chars=0;
      l->complete=0;
      l->end_sorted=NULL;
      l->nested=0;
      l->sorted=START_SORTED;
      l->start_sorted_array=NULL;
}

	
/* 
 * Create's and initializes new gc list.
 * Returns pointer to new list
 */
RegionList *new_region_list(SgrepData *sgrep)
{
      RegionList*l;
      
      l=sgrep_new(RegionList);
      l->sgrep=sgrep;
      init_region_list(l);
      stats.region_lists++; 
      stats.region_lists_now++;
      return l;
}

/*
 * Copies a list of ListNodes. Returns a pointer to first a node.
 * if last is not NULL, returns also a pointer to last node
 */
ListNode *copy_list_nodes(SgrepData *sgrep,const ListNode *n, 
			  ListNode **return_last) {
    ListNode *first=NULL;
    ListNode *last=NULL;

    last=new_list_node(sgrep);
    memcpy(last,n,sizeof(ListNode));
    first=last;
    first->prev=NULL;
    n=n->next;
    while(n) {
	last->next=new_list_node(sgrep);
	memcpy(last->next,n,sizeof(ListNode));
	last->next->prev=last;
	last=last->next;
	n=n->next;
    }
    last->next=NULL;
    if (return_last) {
	*return_last=last;
    }
    return first;
}

/*
 * Turns a gc list to a optimized chars list.
 * in chars list we only tell the length of every region (c->chars)
 * chars list 'contains' every possible region of that size
 * (0,0) (1,1) (2,2) or (1,2) (2,3) (3,4)
 */
void to_chars(RegionList *c,int chars, int end)
{
    SGREPDATA(c);
    assert(c->length==0 && c->last==c->first);
    
    c->chars=chars-1;
    if (c->first!=NULL)
    {
	sgrep_free(c->first);
	c->first=NULL;
	c->last=NULL;
    }
    if (end==0) end=c->length+chars-2;
    c->length=end-chars+2;
    if (c->length<=0)
    {
	/* The gc list became empty, we reinit it to 
	   empty list */
	init_region_list(c);
    }
}

/*
 * Adds a region to gc list 
 * s is start index, e end index
 */
void check_add_region(const RegionList *l, int s, int e)
{
    /* Overkill asserts can save you day */
    assert(l && l->first!=NULL);    
    assert(!l->complete);
    assert(s<=e);
    assert(l->last->next==NULL);
    assert(l->length>=0 || l->length<=LIST_NODE_SIZE);
    
    /* Check that the list will stay start sorted */
    assert(
	l->length==0 || l->sorted!=START_SORTED ||
	LAST_NODE(l).start<s ||
	(LAST_NODE(l).start==s && LAST_NODE(l).end<e));
    

    /* Check that the list is nested only when l->nested is true */
    assert( l->nested || l->length==0 || l->sorted!=START_SORTED ||
	    e>LAST_NODE(l).end);
}

/*
 * Starts a search for regions in a gc list.
 * Inits ListIterator searching handle and returns it
 */
void start_region_search(RegionList *l, ListIterator *handle)
{
    SGREPDATA(l);
    assert(l->last==NULL || l->last->next==NULL);
    assert(l->last!=NULL && l->length<=LIST_NODE_SIZE);
    assert(l->length>=0);

    l->complete=1;
    if (l->sorted!=START_SORTED) {
	get_start_sorted_list(l);
    }
    handle->list=l;
    handle->ind=0;
    handle->node=l->first;
    stats.scans++;
}

/*
 * Starts a search for regions from given index (starting from 0) in
 * region list.
 * Inits ListIterator searching handle and returns it
 */
void start_region_search_from(RegionList *l, int index, ListIterator *handle)
{
    SGREPDATA(l);
    assert(l->last==NULL || l->last->next==NULL);
    assert(l->last!=NULL && l->length<=LIST_NODE_SIZE);
    assert(l->length>=0);

    l->complete=1;
    if (l->sorted!=START_SORTED) {
	get_start_sorted_list(l);
    }
    handle->list=l;
    handle->ind=0;
    handle->node=l->first;
    while(index>=LIST_NODE_SIZE && handle->node->next) {
	handle->node=handle->node->next;
	index-=LIST_NODE_SIZE;
    }
    handle->ind= (index < l->length) ? index : l->length;
    stats.scans++;
}

void start_end_sorted_search(RegionList *l, ListIterator *handle) {
    SGREPDATA(l);
    assert(l->last==NULL || l->last->next==NULL);
    assert(l->last!=NULL && l->length<=LIST_NODE_SIZE);
    assert(l->length>=0);

    l->complete=1;
    if (l->sorted==START_SORTED && !l->nested) {
	start_region_search(l,handle);
	return;
    }
    handle->list=l;
    handle->ind=0;
    handle->node=get_end_sorted_list(l);
    stats.scans++;
}

void list_set_sorted(RegionList *l, enum RegionListSorted sorted) {
    assert(!l->complete);
    l->sorted=sorted;
}

enum RegionListSorted list_get_sorted(const RegionList *l) {
    return l->sorted;
}

#ifdef LAST_REGION_USED
/*
 * NOT USED (yet) and does not work
 * Moves gc lists region pointer to end of list
 *
 */
void last_region(RegionList *l)
{
    assert(l->last==NULL || l->last->next==NULL);
    assert(l->last!=NULL &&l->length<=LIST_NODE_SIZE);
    assert(l->length>=0);

	l->current.ind=l->length;
	l->current.node=l->last;
	stats.scans++;
}
#endif

/*
 * Asserts for get_region, which really is a macro 
 */
#ifndef NDEBUG
void check_get_region(const ListIterator *handle, const Region *reg)
{
    if (handle->list->last!=NULL)
    {
	assert(handle->list->last->next==NULL);
	assert(handle->list->length<=LIST_NODE_SIZE);
	assert(handle->node!=NULL);
	assert(handle->ind<=LIST_NODE_SIZE);
    }
}
#endif

/*
 * asserts for region_at() which really is a macro
 */
#ifndef NDEBUG
int check_region_at(const RegionList *l, int ind) {
    assert(l);
    assert(!l->chars);
    assert(ind>=0 && ind<LIST_SIZE(l));
    assert(l->start_sorted_array && l->start_sorted_array[ind/LIST_NODE_SIZE]);
    return ind;
}
#endif


/*
 * Gives previous region from gc_list pointed by handle.
 * If all regions have been scanned returns (-1,-1) as region
 * NOTE: this function is implemented as a macro in defines.h too, for
 * optimization purposes. However assertions are made only here.
 */
#ifndef NDEBUG
void check_prev_region(const ListIterator *handle,const Region *reg)
{
    if (handle->list->last!=NULL)
    {
	assert(handle->list->last->next==NULL);
	assert(handle->list->length<=LIST_NODE_SIZE);
	assert(handle->node!=NULL);
	assert(handle->ind<=LIST_NODE_SIZE);
    }
    assert(handle->list->length>=0);
    assert(handle->ind>=0);
}
#endif

/*
 * Frees a given gc list by putting its GC_NODE's to free_gc_node list 
 * and freeing GC_LIST node-
 */
void delete_region_list(RegionList *l)
{
    SGREPDATA(l);
#ifdef DEBUG
    if (l->first==NULL)
	fprintf(stderr,"Freeing chars list\n");
    else
	fprintf(stderr,"Freeing a list of size %d regions ..",LIST_SIZE(l));
    fflush(stderr);
#endif
    if (l->start_sorted_array) {
	sgrep_free(l->start_sorted_array);
    }
    while(l->first!=NULL) {
	ListNode *next=l->first->next;
	sgrep_free(l->first);
	l->first=next;
    }
    if (l->end_sorted!=l->first) while (l->end_sorted) {
	ListNode *next=l->end_sorted->next;
	sgrep_free(l->end_sorted);
	l->end_sorted=next;
    }
    sgrep_free(l);
    stats.region_lists_now--;
#ifdef DEBUG
    fprintf(stderr," done\n");
    fprintf(stderr,"There is %d gc lists now\n",gc_lists_now);
#endif
}

/*
 * creates an index table to nodes of a gc list 
 * index table is needed for referencing regions by their number in gc list.
 */
ListNode **create_node_array(const RegionList *s, ListNode *n)
{
	int i;
	ListNode **inds;
	SGREPDATA(s);

#ifdef DEBUG
	fprintf(stderr,"Creating node index .. ");
	fflush(stderr);
#endif
	inds=(ListNode **) sgrep_malloc(sizeof(ListNode *) * s->nodes);
	inds[0]=n;
	for(i=1;i<s->nodes;i++)
		inds[i]=inds[i-1]->next;
#ifdef DEBUG
	fprintf(stderr,"Done\n");
#endif
	return inds;
}

void list_require_start_sorted_array(RegionList *l) {
    l->complete=1;
    /* FIXME: */ assert(!l->chars);
    if (l->start_sorted_array) return;
    if (l->sorted!=START_SORTED) {
	get_start_sorted_list(l);
    }
    assert(l->sorted==START_SORTED && l->first);
    l->start_sorted_array=create_node_array(l,l->first);
}


/*
 * Recursive qsort for gc_list. Needs gc node index table created by
 * create_node_array 
 * A faster way to do this would be nice
 */
enum SortTypes {SORT_BY_START,SORT_BY_END };
void gc_qsort(ListNode **inds,int s,int e, enum SortTypes st)
{
    Region creg,sreg;
    int i,m,last;	
    int r;
    
    if (s>=e) return;
    
    m=(s+e)/2;
    creg=LIST_RNUM(inds,m);
    LIST_RNUM(inds,m)=LIST_RNUM(inds,s);
    LIST_RNUM(inds,s)=creg;
    
    last=s;
    for(i=s+1;i<=e;i++)
    {
	if (st==SORT_BY_START) {
	    r=LIST_RNUM(inds,i).start < creg.start || 
		(LIST_RNUM(inds,i).start==creg.start && LIST_RNUM(inds,i).end<creg.end );
	} else {
	    /* SORT_BY_END */
	    r=LIST_RNUM(inds,i).end < creg.end || 
		(LIST_RNUM(inds,i).end==creg.end && LIST_RNUM(inds,i).start<creg.start );
	}	    
	if ( r )
	{
	    last++;
	    sreg=LIST_RNUM(inds,i);
	    LIST_RNUM(inds,i)=LIST_RNUM(inds,last);
	    LIST_RNUM(inds,last)=sreg;
	}
    }
    sreg=LIST_RNUM(inds,s);
    LIST_RNUM(inds,s)=LIST_RNUM(inds,last);
    LIST_RNUM(inds,last)=sreg;
    gc_qsort(inds,s,last-1,st);
    gc_qsort(inds,last+1,e,st);	
}
	

ListNode *get_end_sorted_list(RegionList *s)
{
    int size;
    ListNode **inds;
    SGREPDATA(s);

    assert(s);
    s->complete=1;
    if (s->sorted==END_SORTED) {
	return s->first;
    }
    if (s->sorted==START_SORTED && (!s->nested)) {
	/* Start sorted non nested list is also end sorted */
	return s->first;
    }    
    size=LIST_SIZE(s);
    if (size<2) {
	/* Only one or zero regions */	
	return s->first;
    }
    if (s->end_sorted) {
	/* Already had end sorted version */
	return s->end_sorted;
    }
    /* Create new copy, only if we need to save start sorted version */
    if (s->sorted==NOT_SORTED) {
	s->sorted=END_SORTED;
	s->end_sorted=s->first;
    } else {
	s->end_sorted=copy_list_nodes(sgrep,s->first,NULL);
    }
    /* Sort the copy */
    inds=create_node_array(s,s->end_sorted); 
    gc_qsort(inds,0,size-1,SORT_BY_END);
    sgrep_free(inds);
    
    stats.sorts_by_end++;
    return s->end_sorted;
}

/*
 * Creates a copy of GC_LIST s which is sorted by it's start points.
 * - if the given gc_list is sorted by end points, it is saved.
 * - otherwise newly created list will be replace old list.
 * - If list already had start sorted version it is returned.
 * - if list length is 0 or 1 same list is returned
 */
ListNode *get_start_sorted_list(RegionList *s)
{   
    int size;
    ListNode **inds;
    SGREPDATA(s);

    assert(s);
    s->complete=1;
    if (s->sorted==START_SORTED) {
	return s->first;
    }
    size=LIST_SIZE(s);
    if (size<2) {
	/* Only one or zero regions */	
	s->sorted=START_SORTED;
	return s->first;
    }
    /* Create new copy, only if we need to save end sorted version */
    if (s->sorted==END_SORTED) {
	assert(s->first==s->end_sorted);
	s->first=copy_list_nodes(sgrep,s->first,NULL);
    }
    s->sorted=START_SORTED;

    /* Sort the copy */
    inds=create_node_array(s,s->first); 
    gc_qsort(inds,0,size-1,SORT_BY_START);
    sgrep_free(inds);
    
    stats.sorts_by_start++;
    return s->first;
}

/*
 * Removes duplica regions from a gc list 
 */
void remove_duplicates(RegionList *s)
{
	ListIterator r,s_handle;
	ListNode *t;
	Region p1,p2;
	SGREPDATA(s);
	
	/* We know only how to remove remove_duplicates from start sorted
	 * lists */
	assert(s);
	start_region_search(s,&r);
	assert(s->sorted==START_SORTED);
	stats.remove_duplicates++;

	start_region_search(s,&s_handle);	
	get_region(&s_handle,&p1);
	while ( p1.start!=-1 )
	{
		get_region(&s_handle,&p2);
		if ( p1.start!=p2.start || p1.end!=p2.end )
		/* Regions p1 and p2 are different */
		{
			if ( r.ind==LIST_NODE_SIZE )
			{
				r.node=r.node->next;
				assert(r.node!=NULL);
				r.ind=0;
			}
#ifdef DEBUG
		fprintf(stderr,"(%d %d)",p1.start,p1.end);
#endif
			r.node->list[r.ind++]=p1;
			p1=p2;
		}
	}
	s->length=r.ind;
	s->last=r.node;
/* free gc blocks which are not needed any more */
	r.node=r.node->next;
	while (r.node!=NULL)
	{
		t=r.node;
		r.node=r.node->next;
		sgrep_free(t);
	}
	s->last->next=NULL;
}

/*
 * Returns argument given to option like -o <arg> or -o<arg> 
 */
char *get_arg(SgrepData *sgrep,char *(*argv[]),int *i,int *j)
{
	char *r;
	
	if ((*(*argv))[*j+1]==0)
	{
		if ( ((*argv)[1])==NULL )
		{
		    sgrep_error(sgrep,"Option -%c requires an argument\n",
				(**argv)[*j]);
		    return NULL;
		}
		r=*(++(*argv));
		(*i)++;
		*j=strlen(r)-1;
	}
	else {
		r=&(*(*argv))[(*j)+1];
		*j=strlen(*(*argv))-1;
	}
#ifdef DEBUG
	fprintf(stderr,"Got argument %s\n",r);
#endif
	return r;
}

/*
 * Expand one backslash escape
 */
int expand_backslash_escape(SgrepData *sgrep, 
			    const unsigned char *list, int *i) {
    int reference=-1;
    int ch;

    if (list[*i]==0) {
	sgrep_error(sgrep,"Backslash at end of string\n");
	return -1;
    }

    ch=list[*i];
    (*i)++;
    switch(ch) {
    case 't': return '\t';
    case 'n': return '\n';
    case 'r': return '\r';
    case 'f': return '\f';
    case 'b': return '\b'; 
    case '\\': return '\\';
    case '\"': return ch='\"';
    case '\n': return '\n';       
    case '#': break;
    default:
	if (isprint(ch)) {
	    sgrep_error(sgrep,"Unknown backslash escape '%c'\n",ch);
	} else {
	    sgrep_error(sgrep,"Unknown blackslash escape #%d\n",ch);
	}
	return -1;
    }

    if (list[*i]==0) {
	sgrep_error(sgrep,"Character reference at end of string\n");
	return -1;
    }
    
    if (list[*i]=='x') {
	/* Hexadecimal character reference */
	reference=0;
	(*i)++;
	while( (list[*i]>='0' && list[*i]<='9') ||
	       ( toupper(list[*i])>='A' && toupper(list[*i])<='F')) {
	    if (list[*i]>='0' && list[*i]<='9') {
		reference=reference*16+list[*i]-'0';
	    } else {
		reference=reference*16+toupper(list[*i])-'A'+10;
	    }
	    (*i)++;
	}
	/* Eat the ';' if there is one */
	if (list[*i]==';') (*i)++;
    } else if (list[*i]>='0' && list[*i]<='9') {
	/* Decimal character reference */
	reference=list[*i]-'0';
	(*i)++;
	while (list[*i]>='0' && list[*i]<='9') {
	    reference=reference*10+(list[*i]-'0');
	    (*i)++;
	}
	/* Eat the ';' if there is one */
	if (list[*i]==';') (*i)++;
    } else if (list[*i]<32) {
	sgrep_error(sgrep,"Invalid character #%d in character list character reference\n",
		    list[*i]);
	return -1;
    } else {
	sgrep_error(sgrep,"Invalid character '%c' in character list character reference\n",
		    list[*i]);
	return -1;
    }

    if (reference>=0xfffe || reference==0) {
	sgrep_error(sgrep,"Character #%d in character list is not an unicode character\n",
		    reference);
	reference=-1;
    }

    return reference;
}

/*
 * Create new SgrepString expanding all backslash escapes
 */
SgrepString *expand_backslashes(SgrepData *sgrep,const char *s) {
    int i=0;
    SgrepString *r;
    const unsigned char *str=(const unsigned char *)s;

    r=new_string(sgrep,strlen(s));
    while(str[i]) {
	if (str[i]=='\\') {
	    int ch;
	    i++;
	    ch=expand_backslash_escape(sgrep,str,&i);
	    if (ch>=0) string_push(r,ch);
	} else {
	    string_push(r,str[i]);
	    i++;
	}
    }
    return r;
}
