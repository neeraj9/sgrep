/*
	System: Structured text retrieval tool sgrep.
	Module: output.c
	Author: Pekka Kilpeläinen & Jani Jaakkola
	Description: handles outputting of a gc list ( show_gclist() )
	Version history: Original version February 1995 by JJ & PK
	Copyright: University of Helsinki, Dept. of Computer Science
*/

/* JJ: Completely rewritten in Sep 11 1998. Using memory mapped files now
 * and much cleaner */

#include <stdio.h>
#include <errno.h>
#include <string.h>
#define SGREP_LIBRARY
#include "sgrep.h"

struct DisplayerStruct {
    struct SgrepStruct *sgrep;
    const FileList *files;
    /* Current region */
    int region;
    /* Current file */
    int current_file;
    int last; /* total length of all files */
    /* 
     * When not in stream mode, the output won't start at position 0.
     * This points out the start of output
     */
    int first_ind;
    /* Remember last_char in case we need to append newline */
    int last_char;
    int start_warned;	/* Has warnings about too long regions been given ? */
    int end_warned;
    FILE *stream; /* The output stream to which we are printing */
    /* The mapped file */
    char *map;
    size_t map_size;
};

/* 
 * Prints a region from file. If necessary opens a new file. Only one file
 * is kept open at a time. s and e are offsets into one file, not into whole
 * input stream. 
 */
const char *get_file_region(Displayer *displayer,int file,
			    unsigned int start, unsigned int len) {
    SGREPDATA(displayer);

    if (displayer->current_file!=file) {
	/* File changed. */
	if (displayer->map) {
	    /* Unmap previous file */
	    unmap_file(sgrep,displayer->map,displayer->map_size);
	    displayer->map=NULL;
	    displayer->map_size=0;
	}
	/* FIXME: handle stdin */
	displayer->current_file=file;
	displayer->map_size=map_file(sgrep,flist_name(displayer->files,
						displayer->current_file),
				     (void **)&displayer->map);
    }
    if (displayer->map==NULL) return NULL; /* Nothing to do without a map */
    if (start>=displayer->map_size || start+len>displayer->map_size) {
	sgrep_error(sgrep,"File '%s' truncated?\n",
		    flist_name(displayer->files,file));
	return NULL;
    }
    return displayer->map+start;
}

void show_file_region(Displayer *displayer,int file,
		      unsigned int start,unsigned int len) {
    const char *r;
    r=get_file_region(displayer,file,start,len);
    if (r) {
	fwrite(r,len,1,displayer->stream);
    }	
}


/*
 * By using constant gc lists it's possible to have regions, which
 * exceed input size. So we need to make a check
 */
void check_region(Displayer *displayer, int *start, int *len)
{
    SGREPDATA(displayer);
    if ( *start>=displayer->last && (!displayer->start_warned) )
    {
	sgrep_error(sgrep,"Warning: region start point greater than input size detected\n");
	displayer->start_warned=1;
	*len=0;
	return;
    }
    if (*start+*len>displayer->last && displayer->end_warned)
    {
	sgrep_error(sgrep,"Warning: region end point greater than input size detected\n");
	displayer->end_warned=1;
	*len=displayer->last-*start;
    }
}

/*
 * Locates and maps the correct file for given region start point
 * assumes start is correct
 */
int locate_file_num(Displayer *displayer, int start) {
    /* Checking the common case: if we already have the right file */
    if (displayer->current_file>=0 && 
	start>=flist_start(displayer->files,displayer->current_file) &&
	start<flist_start(displayer->files,displayer->current_file)+
	flist_length(displayer->files,displayer->current_file)) {
	return displayer->current_file;
    } else {
	/* Do the binsearch */
	return flist_search(displayer->files,start);
    }
}

const char *fetch_region(Displayer *d,Region *region, int *size) {
    int fnum;
    int start,len;
    const char *r;

    if (!region || region->start==-1) {
	*size=0;
	return NULL;
    }
    start=region->start;
    len=region->end-start+1;
    check_region(d,&start,&len);
    if (len<=0) {
	*size=0;
	region->start=region->end=-1;
	return NULL;
    }
    fnum=locate_file_num(d,region->start);
    start-=flist_start(d->files,fnum);
    if (start+len>flist_length(d->files,fnum)) {
	/* Region stretches across files: cut the length */
	len=flist_length(d->files,fnum)-start;
    }
    region->start+=len;
    r=get_file_region(d,fnum,start,len);
    *size= (r)? len : 0;
    return r;
}
	
/*
 * Shows a region which might reside in more than one file. This is done
 * by finding out the files, where region is and calling show_file_region
 */
void show_region(Displayer *displayer,int start,int len)
{
    int fnum;

    check_region(displayer,&start,&len);
    if (len<=0) return;

    fnum=locate_file_num(displayer,start);
    assert(fnum>=0 && fnum<flist_files(displayer->files));
    
    while(len>0) {
	int fstart,flen;	
	fstart=start-flist_start(displayer->files,fnum);
	flen=flist_length(displayer->files,fnum)-fstart;
	if (flen>len) flen=len;
	show_file_region(displayer,fnum,fstart,flen);
	start+=flen;
	len-=flen;
	fnum++;
    }
}	

/* 
 * Handles % commands in output_style string 
 */
void expand(Displayer *displayer, int ch, Region r)
{
    /* FIXME: using direct pointer instead of index (i) might be faster.
     */
    int i=-1;
    
    displayer->last_char=0;
    
    switch (ch) {
    case 'f':
	if (r.start>=displayer->last)
	{
	    fputs("<input exceeded>",displayer->stream);
	    break;
	}
	if (i==-1) i=flist_search(displayer->files,r.start);
	if (i>=0) {
	    const char *name=flist_name(displayer->files,i);
	    if (name) {
		fputs(name,displayer->stream);
	    } else {
		fputs("<stdin>",displayer->stream);
		break;
	    }
	} else {
	    sgrep_error(displayer->sgrep,
			"Could not find file for region (%d,%d)\n",
			r.start,r.end);
	}
	break;
    case 's':
	fprintf(displayer->stream,"%d",r.start+displayer->first_ind);
	break;
    case 'e':
	fprintf(displayer->stream,"%d",r.end+displayer->first_ind);
	break;
    case 'l':
	fprintf(displayer->stream,"%d",r.end-r.start+1);
	break;
    case 'i':
	if (r.start>displayer->last)
	    i=flist_files(displayer->files)-1;
	else if (i==-1) i=flist_search(displayer->files,r.start);
	fprintf(displayer->stream,"%d",
		r.start-flist_start(displayer->files,i));
	break;
    case 'j':
	if (r.end>displayer->last)
	    i=flist_files(displayer->files)-1;
	else if (i==-1) i=flist_search(displayer->files,r.end);
	fprintf(displayer->stream,"%d",
		r.end-flist_start(displayer->files,i));
	break;
    case 'r':
	show_region(displayer,r.start,r.end-r.start+1);
	break;
    case 'n':
	fprintf(displayer->stream,"%d",displayer->region);
	break;
    case '%':
	fputc('%',displayer->stream);
	break;
    default:
	fputc('%',displayer->stream);
	fputc(ch,displayer->stream);
	displayer->last_char=ch;
	break;
    }
}

/* 
 * Handles \ escapes in output_style string 
 * Note: missing \000 - \377 
 */
void escape(Displayer *displayer,int ch)
{
	displayer->last_char=0;
	
	switch (ch) {
	case 'n':
		fputc('\n',displayer->stream);
		displayer->last_char='\n';
		break;
	case 't':
		fputc('\t',displayer->stream);
		break;
	case '\\':
		fputc('\\',displayer->stream);
		break;
	case '\"':
		fputc('\"',displayer->stream);
		break;
	case '\r':
		fputc('\r',displayer->stream);
		break;
	case '\f':
		fputc('\f',displayer->stream);
		break;
	case '\b':
		fputc('\b',displayer->stream);
		break;
	case '%':
		fputc('%',displayer->stream);
		break;
	}
}
	
/*
 * Prints a gc list using output_style and given file list
 */
int display_gc_list(Displayer *displayer,RegionList *l)
{
    ListIterator lp;
    Region r,p;
    int i;
    int ch;
    
    struct SgrepStruct *sgrep=displayer->sgrep;
    
    start_region_search(l,&lp);
    get_region(&lp,&r);
    if (r.start>0 && sgrep->print_all)
    {
	/* There is text before first region */
	show_region(displayer,0,r.start);
    }
    
    if (r.start==-1 && sgrep->print_all) {
	/* There was no regions, but we are in filter mode */
	show_region(displayer,0,displayer->last);
    }
    
    while ( r.start!=-1 && (!ferror(displayer->stream)))
    {
	/* Do the output_style */
	for(i=0;(ch=sgrep->output_style[i]);i++)
	{
	    if ( (ch=='%' || ch=='\\') && sgrep->output_style[i+1] )
	    {
		if (ch=='%') expand(displayer,sgrep->output_style[++i],r);
		if (ch=='\\') escape(displayer,sgrep->output_style[++i]);
	    } else 
	    {
		fputc(ch,displayer->stream);
		displayer->last_char=ch;
	    }
	}
	p=r;
	get_region(&lp,&r);
	
	if (r.start>0 && p.end<r.start-1 && sgrep->print_all)
	{
	    /* There is text between two regions */
	    show_region(displayer,p.end+1,r.start-p.end-1);
	}
	displayer->region++;
    }
    if ((!ferror(displayer->stream)) && 
	r.start==-1 && sgrep->print_all && p.end<displayer->last )
    {
	/* There is text after last region */
	show_region(displayer,p.end+1,displayer->last-p.end-1);
    }
    if ((!ferror(displayer->stream)) &&
	displayer->last_char!='\n' && sgrep->print_newline ) 
	fputc('\n',displayer->stream);
    if ((!ferror(displayer->stream))) fflush(displayer->stream);
    if (ferror(displayer->stream)) {
	sgrep_error(sgrep,"Error writing output: %s\n",strerror(errno));
	return SGREP_ERROR;
    }
    return SGREP_OK;
}

void init_displayer(Displayer *displayer,SgrepData *sgrep, FileList *files) { 
    displayer->sgrep=sgrep;
    displayer->files=files;
    displayer->region=1;
    displayer->current_file=-1;
    displayer->last=flist_total(files);
    displayer->first_ind=0;
    displayer->last_char=0;
    displayer->start_warned=0;
    displayer->end_warned=0;
    displayer->stream=NULL;
    displayer->map=NULL;
    displayer->map_size=0;
}

void clean_up_displayer(Displayer *displayer) {
    SGREPDATA(displayer);
    if (displayer->map!=NULL) {
	unmap_file(sgrep,displayer->map,displayer->map_size);
    }
}

Displayer *new_displayer(SgrepData *sgrep, FileList *files) {
    Displayer *d=sgrep_new(Displayer);
    init_displayer(d,sgrep,files);
    return d;
}

void delete_displayer(Displayer *d) {
    SGREPDATA(d);
    clean_up_displayer(d);
    sgrep_free(d);
}

int write_region_list(struct SgrepStruct *sgrep,
		  FILE *stream, RegionList *list, FileList *files) {
    int r;

    Displayer displayer;
    init_displayer(&displayer,sgrep,files);

    displayer.stream=stream;
    clean_up_displayer(&displayer);
    r=display_gc_list(&displayer,list);
    return r;
}
