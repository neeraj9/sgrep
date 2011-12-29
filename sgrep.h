/*
	System: Structured text retrieval tool sgrep.
	Module: sgrep.h
	Author: Pekka Kilpeläinen & Jani Jaakkola
	Description: Common data structures, definitions & macros for
		     all modules.
	Version history: Original version February 1995 by JJ & PK
	Copyright: University of Helsinki, Dept. of Computer Science
*/


#ifndef SGREP_H_INCLUDED
#define SGREP_H_INCLUDED

#ifdef HAVE_CONFIG_H
# include <config.h>
#endif

#include <stdio.h>
#include <stdlib.h>
#include <assert.h>

#include "sysdeps.h"

/* 
 * Environment variable for specifying options
 */
#define ENV_OPTIONS "SGREPOPT"

/*
 * Get the tmp file directory from this environment variable
 */
#define ENV_TEMP "TEMP"

/*
 * For temp file name generation
 */
#define TEMP_FILE_PREFIX "sg"
#define TEMP_FILE_POSTFIX ".tmp"

/* 
 * If this is TRUE then failure to open a file is considered fatal
 */
#define OPEN_FAILURE 0

/*
 * This spesifies the default amount of RAM-memory available for indexer
 * (-I -m <mem> switch)
 */
#define DEFAULT_INDEXER_MEMORY (20*1024*1024) /* 20 megabytes */
/*
 * The hash table size for indexer term entries
 */
#define DEFAULT_HASH_TABLE_SIZE 1000003

/* 
 * The default output styles
 */
#define LONG_OUTPUT ("------------- #%n %f: %l (%s,%e : %i,%j)\\n%r\\n")
#define SHORT_OUTPUT ( "%r" )


#ifdef __cplusplus
extern "C" {
#endif


/* 
 * This turns on debugging output for all modules. You really don't want
 * to that. Instead define it in the place which you are debugging.
 */
/*#define DEBUG*/

#define SGREP_ERROR -1
#define SGREP_OK 0

/* These are the constant labels */
#define LABEL_NOTKNOWN -1
#define LABEL_CONS 0
#define LABEL_CHARS 1
#define LABEL_PHRASE 2
#define LABEL_FIRST 3

#define LIST_NODE_BITS 7    /* Size of a list node in bits */

/* Sice LIST_NODE_SIZE must be power of 2. So it is calculated from
 * LIST_NODE_BITS 
 */
#define LIST_NODE_SIZE ( 1 << LIST_NODE_BITS )

/*
 * All operators. These are used in the parse tree 
 */
enum Oper { IN,NOT_IN,CONTAINING,NOT_CONTAINING,
	    EQUAL, NOT_EQUAL, /* PK Febr 12 '96 */
	    ORDERED,L_ORDERED,R_ORDERED,LR_ORDERED,
	    QUOTE,L_QUOTE,R_QUOTE,LR_QUOTE,
	    EXTRACTING,
	    OR,
	    PARENTING, CHILDRENING,
	    NEAR, NEAR_BEFORE,
	    OUTER,INNER,CONCAT,
	    JOIN,FIRST,LAST,
	    FIRST_BYTES,LAST_BYTES,
	    PHRASE,
	    INVALID };

/* 
 * Struct for non strings with length.
 */
typedef int SgrepChar;
typedef struct SgrepStringStruct {
    struct SgrepStruct *sgrep;
    size_t size;
    size_t length;
    char *s; /* This contains the sgrep internal encoding of the possibly
	      * 32-wide character */
/* This contains the same string with escape sequences
 * if string_escape() bhas been called */
    struct SgrepStringStruct *escaped;
} SgrepString;
    
/*
 * One region has a start point and a end point 
 */
typedef struct RegionStruct {
	int start;
	int end;
} Region;

/* 
 * One gc node has table for regions and a pointers to next and previous
 * nodes 
 */
typedef struct ListNodeStruct {
	Region list[LIST_NODE_SIZE];
	struct ListNodeStruct *next;
	struct ListNodeStruct *prev;
} ListNode;

/*
 * A pointer to a GC_NODE in a gc list. Used for scanning gc lists.
 */
typedef struct {
        /* list which we are scanning */
	const struct RegionListStruct *list;	
	ListNode *node;	                /* Points out the node */
	int ind;		        /* Index into a node */
} ListIterator;

/*
 * Structure for whole gc list 
 */
enum RegionListSorted { NOT_SORTED, START_SORTED, END_SORTED };
typedef struct RegionListStruct {
    struct SgrepStruct *sgrep;
    int nodes;			/* how many nodes there are */
    int length;			/* How many regions in last node */
    int chars;			/* When we have chars list, this
				   tells from how many characters
				   it is created */
    int refcount;		/* How many times this list is referenced */
    int nested;			/* This list maybe nested */
    enum RegionListSorted sorted;
    int complete;               /* The operation that produced
				 * this list has completed. This
				 * list *may not be changed* anymore */
    ListNode *first;            /* First node in the gc list
				 * NULL means we have an optimized list
				 *  (chars have been used) 
				 */
    ListNode *last;             /* Last node of start sorted list */
    ListNode *end_sorted;       /* If there is a end_point sorted 
				 *  version of this list, this points
				 * to it. Otherwise NULL. */
    struct  RegionListStruct *next; /* We may need to make lists out of gc lists */
    ListNode **start_sorted_array; /* If this region list needs to an
				    * array as well as list*/

} RegionList;

/*
 * Leaves of parse tree are always phrases. 
 */
typedef struct PHRASE_NODE {
    struct PHRASE_NODE *next;	/* Phrase nodes are kept in list for
				   the creation of AC automate */
    SgrepString *phrase;	/* The phrase string */ 
    RegionList *regions;	/* Region list containing matching regions */ 
    /* Pointer to the parse tree node containing this phrase */
    struct ParseTreeNodeStruct *parent;
} ParseTreeLeaf;

/*
 * Node of a parse tree 
 */
typedef struct ParseTreeNodeStruct {
    enum Oper oper;             /* operand */
    
    /* The usual relatives */
    struct ParseTreeNodeStruct *parent;
    struct ParseTreeNodeStruct *left;
    struct ParseTreeNodeStruct *right;

    int label_left;		/* Needed for optimizing */
    int label_right;	        /* me2 */

    int refcount;               /* Parents after common subtree elimination */
    RegionList *result;	        /* If the subtree has been evaluated, this
				 * contains value */
    
    int number;			/* Functions may have int parameters */
    ParseTreeLeaf *leaf;        /* Points to Leaf if this is */
} ParseTreeNode;

/* Opaque FileListStruct for managing lists of sgrep input files
 * defined in common.c */   
struct FileListStruct;
typedef struct FileListStruct FileList;

/* Opaque struct for managing temporary files */
typedef struct TempFileStruct TempFile;

/*
 * Struct for gathering statistical information 
 */
struct Statistics {
    int phrases;	      /* How many phrases found */

    /* Evaluation statistics */
    int operators_evaluated;  /* Total number of operators evaluated */

    int order;		      /* How many operations */
    int or_oper;              /* g++ -ansi complain about plain or... */
    int in;
    int not_in;
    int equal;		      /* PK Febr 12, '96 */
    int not_equal;	      /* PK Febr 12, '96 */
    int containing;
    int not_containing;	
    int extracting;
    int quote;
    int inner;
    int outer;
    int concat;
    int join;
    int parenting;
    int childrening;
    
    /* Statistics about region lists */
    int region_lists;	    /* Number of region lists created */
    int constant_lists;	    /* Number of constant lists */
    int region_lists_now;   /* Number of region lists in use */
    int gc_nodes;	    /* Number of gc_nodes used */
    int gc_nodes_allocated; /* Number of gc_nodes malloced */
    int longest_list;	    /* Longest gc list used */
    int output;		    /* Size of output list */
    int scans;		    /* Number of started scans */
    int scanned_files;      /* Number of scanned files */
    int scanned_bytes;      /* Scanned bytes total */
    int sorts_by_start;	    /* Number of sorts by start points */
    int sorts_by_end;	    /* Number of sorts by end points */
#ifdef OPTIMIZE_SORTS
    int sorts_optimized;	  /* How many sorts we could optimize away */
#endif
    int remove_duplicates;	  /* Number of remove_duplicates operations */
    /* Statistics about the query and it's optimization */
    int parse_tree_size;	  /* Parse tree size */
    int optimized_phrases;        /* How many times we had same phrase */
    int optimized_nodes;	  /* How many parse tree nodes optimized */

    int input_size;		  /* Size of given input in bytes */
    
    /* The memory debugging information is only available if sgrep was
     * compiled with memory-debugging enabled */
#if MEMORY_DEBUG
    int memory_blocks;        /* How many memory blocks allocated now */
    size_t memory_allocated;  /* How much memory allocated now */
    size_t peak_memory_usage; /* Memory usage at worst */
    int reallocs;	      /* how many times memory has been reallocated */
#endif
};

/* 
 * Some handy macros
 */

/*
 * Macro for finding out gc list size 
 */
#define LIST_SIZE(LIST)	(((LIST)->nodes-1)*LIST_NODE_SIZE+(LIST)->length)
/*
 * Macto for last node in list
 */
#define LAST_NODE(LIST) ((LIST)->last->list[(LIST)->length-1])

/* 
 * These are for speeding up list scanning and creation.
 * get_region, add_region and prev_region are the most used
 * functions.
 */

/* Macro for indexing into gc list. */
#define LIST_RNUM(INDS,IND)	( (INDS)[ (IND)>>LIST_NODE_BITS ]-> \
				list[ (IND)& ((1<<LIST_NODE_BITS)-1) ] )

#ifdef NDEBUG
#define add_region(L,S,E) ADD_REGION_MACRO((L),(S),(E))
#define get_region(handle,reg) GET_REGION_MACRO((handle),(reg))
#define prev_region(handle,reg) PREV_REGION_MACRO((handle),(reg))
#define region_at(list,ind,region) REGION_AT_MACRO((list),(ind),(region))
#else  /* NDEBUG not defined */
#define add_region(L,S,E) \
 do {check_add_region(L,S,E); ADD_REGION_MACRO(L,S,E); } while (0)
#define get_region(handle,arg) \
 do {check_get_region(handle,arg); GET_REGION_MACRO(handle,arg); } while (0)
#define prev_region(handle,arg) \
 do {check_prev_region(handle,arg); PREV_REGION_MACRO(handle,arg); } while (0)
#define region_at(list,ind,region) \
 do { check_region_at((list),(ind)); assert((region)!=NULL); \
 REGION_AT_MACRO((list),(ind),(region)); } while (0)
#define region_lvalue_at(LIST,IND) \
  ( ((LIST)->start_sorted_array)[ \
    (check_region_at((LIST),(IND)))>>LIST_NODE_BITS ]-> \
    list[ (IND)& ((1<<LIST_NODE_BITS)-1) ] )
#endif

#define REGION_AT_MACRO(list,ind,region) \
     do { (*region)=LIST_RNUM((list)->start_sorted_array,(ind)); } while(0)

#define REGION_LVALUE_AT_MACRO(list,ind) \
     (LIST_RNUM((list)->start_sorted_array,(ind)))

#define ADD_REGION_MACRO(L,S,E)	do { \
    if ( (L)->length==LIST_NODE_SIZE ) insert_list_node(L); \
    (L)->last->list[(L)->length].start=(S); \
    (L)->last->list[(L)->length].end=(E); \
    (L)->length++; \
} while (0)

#define GET_REGION_MACRO(handle,reg)	\
do { \
	if ( (handle)->node==NULL || (handle)->node->next== NULL ) \
	{ \
		if ((handle)->ind==(handle)->list->length) \
		{ \
			(reg)->start=-1; \
			(reg)->end=-1; \
			break; \
		} \
	 	if ((handle)->list->last==NULL) /* chars list */ \
		{ \
			(reg)->start=(handle)->ind; \
			(reg)->end=(handle)->ind+(handle)->list->chars; \
			(handle)->ind++; \
			break; \
		} \
	} \
	if ( (handle)->ind==LIST_NODE_SIZE ) \
	{ \
		(handle)->node=(handle)->node->next; \
		(handle)->ind=0; \
	} \
	*(reg)=(handle)->node->list[(handle)->ind++]; \
} while(0)

#define PREV_REGION_MACRO(handle,reg) \
do { \
	if ( (handle)->node==NULL || (handle)->node->prev==NULL) \
	{ \
		if ((handle)->ind==0) \
		{ \
			(reg)->start=-1; \
			(reg)->end=-1; \
			break; \
		} \
		if ((handle)->list->first==NULL) \
		{ \
			(handle)->ind--; \
			(reg)->start=(handle)->ind; \
			(reg)->end=(reg)->start+(handle)->list->chars; \
			break; \
		} \
	} \
	if ( (handle)->ind==0 ) \
	{ \
		(handle)->node=(handle)->node->prev; \
		(handle)->ind=LIST_NODE_SIZE; \
	} \
	*(reg)=(handle)->node->list[--(handle)->ind]; \
} while(0)


/* Backward compatibility hack */
#define stats (sgrep->statistics)

typedef enum { SGML_SCANNER, XML_SCANNER, TEXT_SCANNER } ScannerType;

/* The default is to GUESS
 * For XML sgrep guesses UTF8, all others 8-BIT.
 * For XML the encoding declaration is honored, if there is one.
 */
enum Encoding {ENCODING_GUESS, ENCODING_8BIT, ENCODING_UTF8, ENCODING_UTF16};

/*
 * Sgrep has no global variables (outside of main.c), since there exists
 * also a library version of sgrep, which can actually create multiple
 * sgrep instances in different threads
 */
struct MemoryBlockStruct; /* Opaque. See common.c */
typedef struct SgrepStruct {
    char *index_file;                 /* If we have an index_file, this is it's name */
    int recurse_dirs;                 /* Should we recurse into subdirectories (-R) */

    struct Statistics statistics;     /* here we gather statistical					                 information */
    int do_concat;    /* Shall we do concat operation on result list (-d) */
    /* Current IndexReader instance */
    struct IndexReaderStruct *index_reader;
    void (*progress_callback)(void *data,
			    int files_processed, int total_files,
			    int bytes_processed, int total_bytes);   
    void *progress_data;
    FILE *progress_stream; /* stream to write progress reports */
    int progress_output;   /* Should we write progress output */

    SgrepString *error;
    FILE *error_stream;
    char *word_chars;

    char *output_style;		/* String containing the output style
				   default is DEFAULT_OUTPUT */
    int open_failure;		/* So if file that can't be opened
				   is considered to be fatal
				   defaults to OPEN_FAILURE (above)*/
    int print_newline;		/* Shall we print newline at the end of output */
    int print_all;		/* If sgrep is used as a filter */
    int stream_mode; 	        /* Input files considered a stream (-S) */
    
    /* Pmatch.c stuff */
    ScannerType scanner_type;
    int ignore_case;                  /* Ignore case distinctions in phrases */

    /* Default encoding */
    enum Encoding default_encoding;

    /* SGML-stuff */
    int sgml_debug;              /* Enables SGML-scanner debugging */
    int include_system_entities; /* Should scanner include system entities */

/* The historical remain, chars list */
    RegionList *chars_list; 

    /* Points to list of temporary files */
    TempFile *first_temp_file;

    /* The temp file to which stdin is read */
    TempFile *stdin_temp_file;

#ifdef MEMORY_DEBUG
    struct MemoryBlockStruct *m_blocks;  /* A hack for memory bookkeeping */ 
#endif

} SgrepData;

#define MAX_FILE_LIST_FILES 64


/*
 * global function prototypes 
 */

/* Memory management. Beware: I've used some mighty ugly macro magic when
 * debugging sgrep memory usage. Don't do this at home */
#define SGREPDATA(STRUCT) SgrepData *sgrep=((STRUCT)->sgrep)
#define sgrep_new(TYPE) ((TYPE *)sgrep_malloc(sizeof(TYPE)))

#if MEMORY_DEBUG
#define malloc(X) you_should_use_sgrep_malloc_instead_of_plain_malloc()
#define realloc(X,y) you_should_use_sgrep_realloc_instead_of_plain_realloc()
#define free(X) you_should_use_sgrep_free_instead_of_plain_free()
#define calloc(X,Y) you_should_use_sgrep_calloc_instead_of_plain_calloc()
#ifdef strdup
# undef strdup
#endif
#define strdup(X) you_should_use_sgrep_strdup_instead_of_plain_strdup()

void *sgrep_debug_malloc(SgrepData *, size_t, const char *, int);
void *sgrep_debug_calloc(SgrepData *,size_t,size_t);
void *sgrep_debug_realloc(SgrepData *,void *, size_t);
char *sgrep_debug_strdup(SgrepData *,const char *,const char *,int);
void sgrep_debug_free(SgrepData *,void *);
void sgrep_free_all(SgrepData *);
void check_memory_leaks(SgrepData *);
#define sgrep_malloc(X) sgrep_debug_malloc(sgrep,(X),__FILE__,__LINE__)
#define sgrep_calloc(X,Y) sgrep_debug_calloc(sgrep,(X),(Y))
#define sgrep_realloc(X,Y) sgrep_debug_realloc(sgrep,(X),(Y))
#define sgrep_strdup(X) sgrep_debug_strdup(sgrep,(X),__FILE__,__LINE__)
#define sgrep_free(X) sgrep_debug_free(sgrep,(X))

#else /* ! MEMORY_DEBUG */
#define sgrep_malloc(X) malloc(X)
#define sgrep_calloc(X,Y) calloc(X,Y)
#define sgrep_realloc(X,Y) realloc(X,Y)
#define sgrep_strdup(X) strdup(X)
#define sgrep_free(X) free(X)
#endif /* MEMORY_DEBUG */

/*
 * File list management
 */

FileList *new_flist(SgrepData *);
int flist_add(FileList *ifs, const char *name);
int flist_add_relative(FileList *ifs, int relative_to, const char *name);
int flist_exists(FileList *ifs, const char *name);
void flist_add_known(FileList *ifs, const char *name, int len);    
FileList *flist_duplicate(FileList *list);
void flist_cat(FileList *to, FileList *from);
void delete_flist(FileList *list);
void flist_ready(FileList *ifs);
const char *flist_name(const FileList *list, int n);
int flist_length(const FileList *list, int n);
int flist_start(const FileList *list, int n);
int flist_total(const FileList *list);
int flist_files(const FileList *);
int flist_search(const FileList *, int s);
int flist_add_one_file_list_file(FileList *ifs, const char *filename);
int flist_add_file_list_files(FileList *ifs, FileList *file_lists);
int flist_last_errno(const FileList *list);


/*
 * Miscellaneous
 */
char *get_arg(SgrepData *,char *(*argv[]),int *i,int *j);
extern const char *copyright_text[];
FileList *check_files(SgrepData *sgrep,int ,char *[],int,char *[]);
TempFile *create_named_temp_file(SgrepData *sgrep);
TempFile *create_temp_file(SgrepData *sgrep);
int delete_temp_file(TempFile *temp_file);
const char *temp_file_name(TempFile *temp_file);
FILE *temp_file_stream(TempFile *temp_file);
TempFile *temp_file_read_stdin(SgrepData *sgrep);
SgrepString *expand_backslashes(SgrepData *sgrep,const char *str);
int expand_backslash_escape(SgrepData *sgrep, 
			    const unsigned char *list, int *i);

int sgrep_error(SgrepData *,char *format, ...)
#ifdef __GNUC__
                 __attribute__ ((format (printf, 2, 3)))
#endif
;

int sgrep_progress(SgrepData *sgrep, char *format, ...)
#ifdef __GNUC__
                 __attribute__ ((format (printf, 2, 3)))
#endif
;

/* Interface to expression preprocessor */
int preprocess(SgrepData *sgrep, char *,char *,char *,int);

/* Interface to expression parser */
ParseTreeNode *parse_string(SgrepData *sgrep,
			    const char *,struct PHRASE_NODE **);
const char* give_oper_name(int oper);
void free_parse_tree(SgrepData *sgrep,ParseTreeNode *root);

/* Interface to parse tree optimizer */
void optimize_tree(struct SgrepStruct *sgrep,
		   ParseTreeNode **, struct PHRASE_NODE **);

/* This lies in main.c, but since it does both parsing and optimizing */
ParseTreeNode *parse_and_optimize(SgrepData *sgrep,const char *query,
				  struct PHRASE_NODE **phrases);

/* Interface to index modules */
struct IndexReaderStruct;
typedef struct IndexReaderStruct IndexReader;
struct IndexWriterStruct;
struct IndexEntryListStruct;
typedef struct IndexEntryListStruct IndexEntryList;
struct IndexEntryStruct;
typedef struct IndexEntryStruct IndexEntry;

IndexReader *new_index_reader(SgrepData *sgrep,const char *index_file);
void delete_index_reader(IndexReader *reader);
RegionList *index_lookup(IndexReader *reader, const char *phrase);
IndexEntryList *index_term_lookup(IndexReader *reader,
					     const char *first_prefix,
					     const char *last_prefix);
FileList *index_file_list(IndexReader *reader);
int index_list_size(IndexEntryList *);
IndexEntry *index_first_entry(IndexEntryList *);
IndexEntry *index_next_entry(IndexEntry *);
const char *index_entry_term(IndexEntry *);
void delete_index_entry_list(IndexEntryList *l);
/*
 * Indexer Options
 */
enum IndexModes {IM_NONE,IM_CREATE,IM_TERMS,IM_DONE};
typedef struct {
    struct SgrepStruct *sgrep;
    enum IndexModes index_mode;
    int index_stats;     /* Display index statistics? */
    int stop_word_limit;
    const char *input_stop_word_file;
    const char *output_stop_word_file;
    int hash_table_size;
    int available_memory;
    FileList *file_list_files;
    FileList *file_list;
    const char *file_name;
} IndexOptions;
void set_default_index_options(SgrepData *sgrep,IndexOptions *o);
int create_index(const IndexOptions *options);
int add_region_to_index(struct IndexWriterStruct *writer,
		      const char *str, int start, int end);
/* More functions to handle IndexEntries might be added later */


/* Interface to pattern matching module */
void print_scanner_help();
int set_scanner_option(SgrepData *sgrep,const char *arg);
int search(SgrepData *sgrep,struct PHRASE_NODE *, FileList *, 
	   int f_file, int l_files);
int index_search(SgrepData *sgrep, struct IndexWriterStruct *writer, 
		 FileList *files);

/* Interface to SGML scanner module */
struct SGMLScannerStruct;
typedef struct SGMLScannerStruct SGMLScanner;
SGMLScanner *new_sgml_phrase_scanner(SgrepData *sgrep,
				     FileList *file_list,
				     struct PHRASE_NODE *list);
SGMLScanner *new_sgml_index_scanner(SgrepData *sgrep,
				    FileList *file_list,
				    struct IndexWriterStruct *writer); 
int sgml_scan(SGMLScanner *scanner,
	      const unsigned char *buf, 
	      int len, 
	      int start,
	      int file_num);
void sgml_flush(SGMLScanner *sgmls);
void delete_sgml_scanner(SGMLScanner *s);

/* Interface to string handler */
SgrepString *new_string(SgrepData *sgrep,size_t size);
SgrepString *init_string(SgrepData *,size_t size,const char *src);
void push_front(SgrepString *s,const char *str);
void delete_string(SgrepString *str);
void string_cat(SgrepString *s, const char *str);
/* FIXME: string_push() probably needs to be implemented inline */
void real_string_push(SgrepString *s, SgrepChar ch);
void string_clear(SgrepString *s);
void string_tolower(SgrepString *s,int);
void string_toupper(SgrepString *s,int);
#define string_clear(S) ((S)->length=0)
#define string_truncate(S,LEN) ((S)->length=(LEN))
#define string_to_char(S) ((S)->s[(S)->length]=0,(const char *)(S)->s)
#define string_len(STR) ((STR)->length)
const char *string_escaped(SgrepString *s);
void string_cat_escaped(SgrepString *escaped, const char *str);


/* #define string_push(STR,CHAR) real_string_push((STR),(CHAR)) */
#define string_push(STR,CHAR) do { \
if ((STR)->length<(STR)->size && (CHAR)<255) { \
        (STR)->s[(STR)->length]=(CHAR); \
        (STR)->length++; \
    } else { real_string_push((STR),(CHAR)); } \
} while (0)


/* Manipulation of region lists */
RegionList *new_gclist();
RegionList *new_region_list(SgrepData *sgrep);
void delete_region_list(RegionList *l);
#define free_gclist(LIST) delete_region_list(LIST)
void list_require_start_sorted_array(RegionList *l);
RegionList *merge_region_lists(RegionList *list1, RegionList *list2);

/* Region adding and scanning */

void insert_list_node(RegionList *l);
void start_region_search(RegionList *, ListIterator *);
void start_region_search_from(RegionList *, int index, ListIterator *);
void start_end_sorted_search(RegionList *,ListIterator *);
void list_set_sorted(RegionList *l, enum RegionListSorted);
enum RegionListSorted list_get_sorted(const RegionList *l);
void remove_duplicates(RegionList *);
void to_chars(RegionList *,int chars, int end);

/* These functions perform sanity checks, and are not even compiled in,
 * if NDEBUG is defined */
#ifndef NDEBUG
void check_add_region(const RegionList *, int start, int end);
void check_get_region(const ListIterator *, const Region *);
void check_prev_region(const ListIterator *, const Region *);
int check_region_at(const RegionList *, int);
#endif

/* Interface to evaluator module */
RegionList *eval(struct SgrepStruct *, const FileList *,ParseTreeNode *);

/* Interface to output module */
typedef struct DisplayerStruct Displayer;
Displayer *new_displayer(SgrepData *sgrep, FileList *files);
void delete_displayer(Displayer *displayer);
const char *fetch_region(Displayer *d,Region *, int *len);

int write_region_list(struct SgrepStruct *sgrep,FILE *, 
		  RegionList *, FileList *);
    

/* Interface to sysdeps module */
size_t map_file(SgrepData *sgrep, const char *filename,void **map);
int unmap_file(SgrepData *sgrep, void *map, size_t size);



#ifdef __cplusplus
}
#endif

#ifdef __cplusplus
/* Hack to shut up some stupid C++ warnings */
/*
#include <string.h>
inline int strlen(const unsigned char *s) {
    return strlen((const char *)s);
}
inline int strcmp(const unsigned char *s1, const unsigned char *s2) {
    return strcmp((const char *)s1,(const char *)s2);
}
inline int strncmp(const unsigned char *s1, const unsigned char *s2, int i) {
    return strncmp((const char *)s1,(const char *)s2,i);
}
inline unsigned char *strncpy(unsigned char *dest, const unsigned char *src,
			      int n) {
    return (unsigned char *)strncpy((char *)dest,(const char *)src,n);
}
inline char *sgrep_debug_strdup(SgrepData *sgrep, const char *s) {
    return (char *)sgrep_debug_strdup(sgrep,(const unsigned char *)s);
}
inline int fputs(const unsigned char *s, FILE *stream) {
    return fputs((const char *)s,stream);
}
*/
#endif

#endif /* SGREP_H_INCLUDED */
