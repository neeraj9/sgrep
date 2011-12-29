/*
	System: Structured text retrieval tool sgrep.
	Module: pmatch.c
	Author: Pekka Kilpeläinen & Jani Jaakkola
	Description: Pattern matching using Aho-Corasick automate (ACsearch() )
	Version history: Original version February 1995 by JJ & PK
	Copyright: University of Helsinki, Dept. of Computer Science
		   Distributed under GNU General Public Lisence
		   See file COPYING for details
*/

/* NOTE: Aho-Corasick automate can only take constant patterns. There is
         no wild card expansions and it's always case sensitive. Maybe
         something should be done about this.
*/

/*
 * NOTE: This module is used both by normal query engine and indexing
 * engine. query engine accesses this module through search().
 * Interface to indexer is a bit awkward: index.c calls index() function
 * to start scanning files and this module calls add_region_index() 
 * to add the newly found regions to index. This is a bit awkward and
 * possibly also somewhat (little?) inefficient.
 */


#include <stdio.h>
#include <string.h>
#include <ctype.h>

#define SGREP_LIBRARY
#include "sgrep.h"

/*
 * Private data structures
 */

/* Scanbuffer is for reading files */
struct ScanBuffer {
    SgrepData *sgrep;
    FileList *file_list;
    int len;
    int file_num;
    int old_file_num;
    int last_file;
    int region_start;
    const unsigned char *map;
    int map_size;
};


/* OutputList, ACState and ACScanner are for Aho-Corasick automate */
struct OutputList {
	struct PHRASE_NODE *phrase;
	struct OutputList *next;
};

struct ACState {
    struct ACState *gotos[256];
    struct ACState *fail;
    struct ACState *next; /* queue needed when creating fail function */
    struct OutputList *output_list;
#ifdef DEBUG
    int state_num;
#endif
};

struct ACScanner {
    SgrepData *sgrep;
    struct PHRASE_NODE *phrase_list; /* Points to this scanners phrase list */
    struct ACState *root_state; /* Points to root state */
    struct ACState *s;          /* Points to current state */
    int ignore_case;
} AC_scanner; /* THE AC_scanner, since only one is needed */


/*
 * Private prototypes
 */
void new_output( SgrepData *sgrep, struct ACState *s, 
			struct PHRASE_NODE *pn);
void ACsearch(struct ACScanner *scanner, const unsigned char *buf, 
	      int len, int start);
void enter(SgrepData *sgrep, struct PHRASE_NODE *pn, 
		  struct ACState *root_state, int ignore_case);
void create_fail(SgrepData *sgrep, struct ACState *root_state);
void create_goto(SgrepData *sgrep,struct PHRASE_NODE *phrase_list, 
			struct ACState *root_state,
			int ignore_case);

#ifdef DEBUG
void show_states(int depth,struct State_Data *s);
void show_ACtree();
void show_outputs(struct State_Data *s);
#endif



void print_scanner_help() {
    printf("      %-12s%s\n","sgml","use SGML scanner");
    printf("      %-12s%s\n","html","use HTML scanner (currently same as sgml scanner)");
    printf("      %-12s%s\n","xml","use XML scanner");
    printf("      %-12s%s\n","sgml-debug","show recognized SGML tokens");
    printf("      %-12s%s\n","include-entities","  automatically include system entities");
}

int set_scanner_option(SgrepData *sgrep,const char *a) {
    int i;
    char *arg=sgrep_strdup(a);
    for(i=0;arg[i];i++) arg[i]=tolower(arg[i]);

    if ( strcmp(arg,"sgml")==0 || 
	 strcmp(arg,"html")==0) {
	sgrep->scanner_type=SGML_SCANNER;
    } else if (strcmp(arg,"xml")==0) {
	sgrep->scanner_type=XML_SCANNER;
    } else if (strcmp(arg,"text")==0) {
	sgrep->scanner_type=TEXT_SCANNER;	
    } else if (strcmp(arg,"sgml-debug")==0) {
	sgrep->sgml_debug=1;
    } else if (strcmp(arg,"include-entities")==0) {
	sgrep->include_system_entities=1;
    } else if (strcmp(arg,"encoding=iso-8859-1")==0) {
	sgrep->default_encoding=ENCODING_8BIT;
    } else if (strcmp(arg,"encoding=utf8")==0) {
	sgrep->default_encoding=ENCODING_UTF8;
    } else if (strcmp(arg,"encoding=utf16")==0) {
	sgrep->default_encoding=ENCODING_UTF16;
    } else {
	sgrep_error(sgrep,"Unknown scanner argument '%s'\n",arg);
	sgrep_free(arg);
	return SGREP_ERROR;
    }
    sgrep_free(arg);
    return SGREP_OK;
}

/*
 * Creates and initializes a new scanner buffer struct with given
 * input files
 */
struct ScanBuffer *new_scan_buffer(SgrepData *sgrep,FileList *files) {
    struct ScanBuffer *sc;
    sc=sgrep_new(struct ScanBuffer);
    sc->sgrep=sgrep;
    sc->file_list=files;
    sc->len=0;
    sc->file_num=0;
    sc->old_file_num=-1;
    sc->last_file=-1; /* As many files there is in list */
    sc->region_start=0;
    sc->map=NULL;
    sc->map_size=0;
    return sc;
}

struct ScanBuffer *reset_scan_buffer(struct ScanBuffer *sc, 
				     int f_file, int l_file) {
    sc->file_num=f_file;
    sc->last_file=l_file;
    sc->region_start=flist_start(sc->file_list,f_file);
    return sc;
}


void delete_scan_buffer(struct ScanBuffer *b) {
    SgrepData *sgrep=b->sgrep;
    sgrep_free(b);
}

/*
 * Fills the scanner input buffer and sets len and file_num respectively
 * if all files have been processed returns 0
 * otherwise returns number of bytes available in buffer
 * NEW: uses map_file() instead of read()
 */
int next_scan_buffer(struct ScanBuffer *sb)
{
    SGREPDATA(sb);
    if (sb->map && sb->len==sb->map_size) {
	sb->file_num++;
    }
    /* Skip zero length files */
    while(sb->file_num<flist_files(sb->file_list) &&
	  flist_length(sb->file_list,sb->file_num)==0) {
	sb->file_num++;
    }
    if (sb->old_file_num!=sb->file_num && sb->map) {
	unmap_file(sgrep,(void *)sb->map,sb->map_size);
	sb->map=NULL;
	sb->map_size=0;
    }
    if ( (sb->last_file==-1 && sb->file_num>=flist_files(sb->file_list)) ||
	 (sb->last_file>=0 && sb->file_num>sb->last_file) ) {
	/* All files scanned */
	return 0;
    }
    if (!sb->map) {
	void *map;
	sb->map_size=map_file(sgrep,flist_name(sb->file_list,sb->file_num),
			      &map);
	sb->map=(const unsigned char*)map;
    }
    if (sb->map==NULL) {
	sgrep_error(sgrep,"Failed to scan file '%s'\n",
		    flist_name(sb->file_list,sb->file_num));
	return SGREP_ERROR;
    }
    sb->old_file_num=sb->file_num;
    if (sb->map_size!=flist_length(sb->file_list,sb->file_num)) {
	sgrep_error(sgrep,"Size of file '%s' has changed\n",
		    flist_name(sb->file_list,sb->file_num));
    }
    sb->region_start+=sb->len;
    sb->len=sb->map_size;
    return sb->len;
}
		
/*
 * Gives and inits a new state to the automate.
 */
/* If root_state is NULL
 * it inits the root_state 
 */
struct ACState *new_state(SgrepData *sgrep)
{
	int i;
	struct ACState *s;
#ifdef DEBUG
	static int snum;
#endif
	s=(struct ACState *)sgrep_malloc( sizeof(struct ACState));
	for (i=0;i<256;i++) s->gotos[i]=NULL;
	s->output_list=NULL;
	s->next=NULL;
	s->fail=NULL;
#ifdef DEBUG
	snum++;
	s->state_num=snum;
#endif
	return s;
}

/*
 * Enters a new output link to a state 
 */
void new_output(SgrepData *sgrep, struct ACState *s, struct PHRASE_NODE *pn)
{
	struct OutputList **op;

	op=&s->output_list;
	while (*op!=NULL) op=& (*op)->next;
	*op=sgrep_new(struct OutputList);
	(*op)->next=NULL;
	(*op)->phrase=pn;
}

/*
 * Enters a new phrase to automate given with root_state
 */
void enter(SgrepData *sgrep, struct PHRASE_NODE *pn, 
	   struct ACState *root_state,
	   int ignore_case)
{
	struct ACState *state=root_state;
	size_t j;
	unsigned char pch;

#ifdef DEBUG
	printf("enter %s",str);
#endif
	assert(pn->phrase->s[0]=='n');
	j=1;
	pch=pn->phrase->s[j];
	if (ignore_case) pch=toupper(pch);
	while ( state->gotos[pch]!=NULL && j<pn->phrase->length )
	{
		state=state->gotos[pch];
		j++;
		pch=pn->phrase->s[j];
		if (ignore_case) pch=toupper(pch);
	}
	
	while( j<pn->phrase->length )
	{
		state->gotos[pch]=new_state(sgrep);
		state=state->gotos[pch];
		j++;
		pch=pn->phrase->s[j];
		if (ignore_case) pch=toupper(pch);
	}
	new_output(sgrep,state,pn);
#ifdef DEBUG
	printf(" done\n");
#endif
}
	
/*
 * The creation of the AC goto function using the enter function 
 * and the phrase list. 
 * The automate is spesified with root_state
 */
void create_goto(SgrepData *sgrep, struct PHRASE_NODE *phrase_list,
		 struct ACState *root_state,
		 int ignore_case)
{
	struct PHRASE_NODE *pn;

	for(pn=phrase_list;pn!=NULL;pn=pn->next) {
	    if (pn->phrase->s[0]=='n') {
		/* Add only AC phrases to automate */
#if DEBUG
		fprintf(stderr,"AC phrase:%s\n",lpn->phrase->s);
#endif		
		enter(sgrep,pn,root_state,ignore_case);
	    }
	}
}

/*
 * The creation of the AC fail function and the final output function 
 * The automate to use is given with root_state
 */
void create_fail(SgrepData *sgrep,struct ACState *root_state) 
{
	int i;
	struct ACState *s,*r,*state;
	struct ACState *first=NULL;
	struct ACState *last=NULL;	
	struct OutputList *op;
	
#ifdef DEBUG
	printf("Create fail :");
#endif	
	for (i=0;i<256;i++)
	{
		if ( (s=root_state->gotos[i]) !=root_state )
		{		
			if (first==NULL) first=s;
			if (last!=NULL) last->next=s;
			last=s;
			last->next=NULL;
			s->fail=root_state;
		}
	}
#ifdef DEBUG
	printf(" root done");
#endif
	while (first!=NULL)
	{
		r=first;
		first=first->next;
		for (i=0;i<256;i++) if ( r->gotos[i]!=NULL )
		{
			s=r->gotos[i];
			last->next=s;
			last=s;
			last->next=NULL;
			if (first==NULL) first=last;
			state=r->fail;
			while (state->gotos[i]==NULL) state=state->fail;
			s->fail=state->gotos[i];
			for (op=s->fail->output_list;
			     op!=NULL;
			     op=op->next) {
			    assert(op->phrase!=NULL);
			    new_output(sgrep,s,op->phrase);
			}
		}
	}
#ifdef DEBUG
	printf(", all done\n");
#endif
}

/* Phrases list points to list of phrases to be
 * matched. ifs points to names of input files, and lf is the number of
 * input files.
 */
struct ACScanner *init_AC_search(SgrepData *sgrep,
				 struct PHRASE_NODE *phrase_list) {
    int i;
    struct ACScanner *sc;

    sc=sgrep_new(struct ACScanner);
    sc->sgrep=sgrep;
    sc->root_state=new_state(sgrep);
    sc->phrase_list=phrase_list;
    sc->s=sc->root_state;
    sc->ignore_case=sgrep->ignore_case;
    create_goto(sgrep,phrase_list,sc->root_state,sc->ignore_case);
    /* there isn't any fail links from root state */
    for (i=0;i<256;i++) {
	if (sc->root_state->gotos[i]==NULL) 
	    sc->root_state->gotos[i]=sc->root_state;
    }
    create_fail(sgrep,sc->root_state);
    return sc;
}

void delete_AC_state(SgrepData *sgrep,struct ACState *as) {
    int i;
    for(i=0;i<256;i++) {
	if (as->gotos[i] && as->gotos[i]!=as) {
	    delete_AC_state(sgrep,as->gotos[i]);
	}
	while(as->output_list) {
	    struct OutputList *ol=as->output_list;
	    as->output_list=as->output_list->next;
	    sgrep_free(ol);
	}
    }
    sgrep_free(as);
}
	
void delete_AC_scanner(struct ACScanner *ac) {
    /* FIXME: this leaks memory! */
    SGREPDATA(ac);
    delete_AC_state(sgrep,ac->root_state);
    sgrep_free(ac);
}


/* 
 * The AC automate search. 
 * (A dramatically simpler version, than which it used to be four years
 *  ago when it first saw the light of the day.
 *  It seems that i've actually gained some "programming experience"
 *  in these years :) 
 */
void ACsearch(struct ACScanner *scanner, const unsigned char *buf, 
	      int len, int start)
{
    struct OutputList *op;
    int ch;
    int i;
    struct ACState *s;

    s=scanner->s;
    for(i=0;i<len;i++) {
	ch=(scanner->ignore_case) ? toupper(buf[i]) : buf[i];
	while (s->gotos[ch]==NULL) {
	    assert(s->fail);
	    s=s->fail;
	}	
	s=s->gotos[ch];
	op=s->output_list;
	while(op!=NULL) {
	    scanner->sgrep->statistics.phrases++;
	    assert(op->phrase->regions!=NULL);
	    add_region( op->phrase->regions,
			i-(op->phrase->phrase->length-1)+start+1,
			i+start);
#ifdef DEBUG
	    printf("Found \"%s\" in file %s at %d  gc<-(%d,%d)\n",
		   op->phrase->phrase->s,
		   file_list->files[file_num].name,
		   file_pos-buf_end+buf_pos-(op->phrase->phrase->length),
		   i- ( op->phrase->phrase->length ) , i-1);
#endif
	    op=op->next;
	} while ( op!=NULL );
    }
    scanner->s=s;
}


int search(SgrepData *sgrep,struct PHRASE_NODE *phrase_list, FileList *files, 
	   int f_file, int l_file) {
    int sgml_phrases;
    int regex_phrases;
    int ac_phrases;
    int file_phrases;
    int e=SGREP_OK;
    int previous_file=-1;

    /* If there is no phrases, there is no point to do searching */
    if (phrase_list==NULL) {
	sgrep_progress(sgrep,"No phrases. Skipping search\n");
	return SGREP_OK;
    }
    if (sgrep->index_file==NULL) {
	struct ScanBuffer *sb=NULL;
	struct ACScanner *acs=NULL;
	SGMLScanner *sgmls=NULL;
	struct PHRASE_NODE *j=NULL;

	file_phrases=ac_phrases=sgml_phrases=regex_phrases=0;

	/* We have to create empty gc lists for phrases */
	for (j=phrase_list;j!=NULL;j=j->next)
	{
	    assert(j->regions==NULL);
	    j->regions=new_region_list(sgrep);
	    if (j->phrase->s[0]=='@' ||
		j->phrase->s[0]=='*') {
		list_set_sorted(j->regions,NOT_SORTED);
		j->regions->nested=1;
	    }
	    
	    switch (j->phrase->s[0]) {
	    case 'n':
		ac_phrases++;
		break;
	    case 'r':
		regex_phrases++;
		break;
	    case 'f':
		file_phrases++;
		break;
	    case '#':
		/* Input independent phrases */
		break;
	    default:
		sgml_phrases++;
	    }	
	}

	/* Initialization */
	sb=new_scan_buffer(sgrep,files);
	reset_scan_buffer(sb,f_file,l_file);
	if (ac_phrases) {
	    acs=init_AC_search(sgrep,phrase_list);
	}
	if (sgml_phrases) {
	    sgmls=new_sgml_phrase_scanner(sgrep,files,phrase_list);
	}
	
	/* Main scanning loop, only if there is something to scan */
	if (acs || sgmls) while((e=next_scan_buffer(sb))>0) {
	    if (flist_files(files)>1) {
		sgrep_progress(sgrep,"Scanning %d/%d files %d/%dK (%d%%)\n",
			       sb->file_num,flist_files(files),
			       sb->region_start/1024,flist_total(files)/1024,
			       sb->region_start/(flist_total(files)/100+1));
	    } else {
		sgrep_progress(sgrep,"Scanning file '%s' %d/%dK (%d%%)\n",
			       flist_name(sb->file_list,sb->file_num),
			       sb->region_start/1024,flist_total(files)/1024,
			       sb->region_start/(flist_total(files)/100+1));
	    }		    
	    if (sgrep->progress_callback) {
		sgrep->progress_callback(sgrep->progress_data,
					 sb->file_num,flist_files(files),
					 sb->region_start,flist_total(files)); 
	    }			     	    
	    if (ac_phrases) {
		ACsearch(acs,sb->map,sb->len,sb->region_start);
	    }
	    if (sgml_phrases) {
		if (previous_file!=-1 && sb->file_num!=previous_file) {
		    sgml_flush(sgmls);
		}
		previous_file=sb->file_num;
		sgml_scan(sgmls,sb->map,sb->len,sb->region_start,sb->file_num);
	    }
	}
#if 0
	/* FIXME: think this over */
	if (sgmls && sgmls->parse_errors>0) {
	    fprintf(stderr,"There was %d SGML parse errors\n",
		    sgmls->parse_errors);
	}
#endif
	/* Clean up scanners */
	delete_scan_buffer(sb);
	if (sgmls) {
	    sgml_flush(sgmls);
	    delete_sgml_scanner(sgmls);
	}	
	if (acs) delete_AC_scanner(acs);

	/* Now handle the phrases, whose contents we know only after
	 * scanning or which are independent of scanning */
	/* FIXME and include-entities will break this */
	for(j=phrase_list;j!=NULL; j=j->next) {

	    switch(j->phrase->s[0]) {

	    case '#':
		if (strcmp(j->phrase->s,"#start")==0) {
		    int start=flist_start(files,f_file);
		    add_region(j->regions,start,start);
		} else if (strcmp(j->phrase->s,"#end")==0) {
		    int last=flist_start(files,l_file)+
			flist_length(files,l_file)-1;
		    add_region(j->regions,last,last);
		} else {
		    sgrep_error(sgrep,"Don't know how to handle phrase %s\n",
				j->phrase->s);
		}
		break;
		
	    case 'f': {
		int f;	       
		for(f=f_file;f<=l_file;f++) {
		    /* Check for filename */
		    if (j->phrase->s[j->phrase->length-1]=='*') {
			/* Wildcard */
			if (strncmp((char *)j->phrase->s+1,flist_name(files,f),
				    j->phrase->length-2)==0 &&
			    flist_length(files,f)>0) {
			    add_region(j->regions,
				       flist_start(files,f),
				       flist_start(files,f)+
				       flist_length(files,f)-1);
			}
		    } else if (strcmp((char *)j->phrase->s+1,
				      flist_name(files,f))==0 &&
			       flist_length(files,f)>0) {
			add_region(j->regions,
				   flist_start(files,f),
				   flist_start(files,f)+
				   flist_length(files,f)-1);
		    }
		}
	    }
	    break;
	    }
	}
    } else {
	sgrep_progress(sgrep,"Using lazy index file mode\n"); 
	e=SGREP_OK;
    }
    return (e==SGREP_ERROR) ? SGREP_ERROR:SGREP_OK;
}

/* FIXME: merge this better with search() */
int index_search(SgrepData *sgrep,struct IndexWriterStruct *writer,
		  FileList *files) {
    struct ScanBuffer *sb;
    int previous_file=-1;
    SGMLScanner *sgmls;

    sb=new_scan_buffer(sgrep,files);
    sgmls=new_sgml_index_scanner(sgrep,files,writer);
    while(next_scan_buffer(sb)>0) {
	if (previous_file!=-1 && sb->file_num!=previous_file) {
	    sgml_flush(sgmls);
	}
	previous_file=sb->file_num;
	sgrep_progress(sgrep,"Indexing file %d/%d '%s' %d/%dK (%d%%)\n",
		      sb->file_num+1,flist_files(files),
		       flist_name(files,sb->file_num),
		      sb->region_start/1024,flist_total(files)/1024,
		      sb->region_start/(flist_total(files)/100+1));	
	if (sgrep->progress_callback) {
	    sgrep->progress_callback(sgrep->progress_data,
				     sb->file_num,flist_files(files),
				     sb->region_start,flist_total(files)); 
	}
	if (sgml_scan(sgmls,sb->map,sb->len,sb->region_start,sb->file_num)
	    ==SGREP_ERROR) {
	    delete_scan_buffer(sb);
	    delete_sgml_scanner(sgmls);
	    return SGREP_ERROR;
	}
    }
    sgml_flush(sgmls);
    delete_scan_buffer(sb);
    delete_sgml_scanner(sgmls);
    return SGREP_OK;
}


#ifdef DEBUG
/*
 * These are (were) used for debugging the creation of ac-automate
 */
void show_ACtree()
{
	printf("-------------------\n AC-tree\n------------------\n");
	show_states(0,root_state);
	show_outputs(root_state); 
}

void show_states(int depth,struct State_Data *s)
{
	int end=0;
	int i,j;
	
	for(i=0;i<256;i++)
	{
		if (s->gotos[i]!=NULL && 
		   !( s==root_state && s->gotos[i]==root_state ) )
		{
			if (end>0)
			for (j=0;j<depth;j++) printf("                ");
			printf("%2d:f=%2d:",s->state_num,s->fail->state_num);
			end++;
			printf("%c->%2d , ",i,s->gotos[i]->state_num);
			show_states(depth+1,s->gotos[i]);
		}
	}
	if (!end)
	{
		printf("%2d:f=%2d <---\n",s->state_num,s->fail->state_num);
	}
}

void show_outputs(struct State_Data *s)
{
	int i;
	struct OutPut *op;
	
	op=&s->out_list;
	if (op->phrase!=NULL)
	{
		printf("state %d:",s->state_num);
		do {
			printf(" %s",op->phrase->phrase->s);
			op=op->next;
		} while ( op!=NULL );
		printf("\n");
	}
	
	for (i=0;i<256;i++)
	{
		if (s->gotos[i]!=NULL && s->gotos[i]!=root_state )
			show_outputs(s->gotos[i]);
	}
}		
#endif
