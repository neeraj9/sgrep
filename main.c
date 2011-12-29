/*
        System: Structured text retrieval tool sgrep.
	Module: main.c
	Author: Pekka Kilpeläinen & Jani Jaakkola
	Description: Command line parsing. All work is done elsewhere
		     	pattern matching, evaluation and output
	Version history: Original version February 1995 by JJ & PK
	Copyright: University of Helsinki, Dept. of Computer Science
*/

#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <fcntl.h>
#include <string.h>
#include <limits.h>

#include "sgrep.h"

#if HAVE_SYS_TIMES_H
#include <sys/times.h>
#endif

#if HAVE_UNISTD_H
#include <unistd.h>
#endif

extern int index_main(SgrepData *,int argc, char **argv);

/*
 * struct for list of expression strings ( or files ) to be executed 
 */
enum ExpressionType { E_FILE,E_TEXT };
struct Expression {
    enum ExpressionType type; /* If this is a file, or command line */
    char *expr; 	      /* Pointer to either filename or expression */
    struct Expression *next;
};

void show_stats();
void show_times();
int get_options(char *[]);
void add_command(char *);
SgrepString *read_expressions(SgrepData *sgrep,
			      struct Expression *expression_list);
int environ_options();
int run_stream(FileList *files, ParseTreeNode *, struct PHRASE_NODE *p_list);
int run_one_by_one(FileList *files, ParseTreeNode *, 
		   struct PHRASE_NODE *p_list);
void create_constant_lists();
void delete_constant_lists();


/*
 * Global variables used inside main.c . These are mainly used for storing
 * information about given options
 */
SgrepData *sgrep;

int have_stats=0;	/* Should we show statistics in the end (-T) */
int have_times=0;       /* Should we show info about used time in the end (-t) */
int display_count=0;    /* Should we display only count of matching regions (-c) */
int no_output=0;        /* Should we supress normal output (-q) */
int show_expr=0;	/* only show expression, don't execute it (-P) */

/* Which preprocessor to use (-p) */
char *preprocessor=DEFAULT_PREPROCESSOR; 
int read_sgreprc=1; 	/* are we going to read sgreprc (-n) */
char *option_space=NULL;        /* Allocated if SGREPOPT is used */

/* List of expressions */
struct Expression *last_expression=NULL;

int num_file_list_files=0;
char *file_list_files[MAX_FILE_LIST_FILES];

#if HAVE_TIMES
/*
 * Struct for time information 
 */
struct time_points {
	struct tms start;
	struct tms parsing;
	struct tms acsearch;
	struct tms eval;
	struct tms output;
} tps;
#else
#define CALC_TIME(X) /* Nothing */
#define times(X) /* Nothing */
#endif


/* 
 * Struct for options 
 */
struct OptionData {
	char opt;
	char *have_param;
	char *what_does;
};

/*
 * List & description of options
 * If you add more options, add the descriptions here. Put the implementation
 * of option in get_options() 
 */
const struct OptionData option_data[]= {
	{ 'a',NULL,"act as a filter" },
#if 0
	{ 'C',NULL,"display copyright notice" },
#endif
	{ 'c',NULL,"display only count of matching regions" },
	{ 'D',NULL,"obsolete synonym for -v"},
	{ 'd',NULL,"don't do concat on result list"},
	{ 'h',NULL,"help (means this text)" },
	{ 'i',NULL,"ignore case distinctions in phrases" },
	{ 'I',NULL,"switches to indexing mode, when given as first option" },
	{ 'l',NULL,"long output format" },
	{ 'N',NULL,"don't add trailing newline" },
	{ 'n',NULL,"don't read $HOME/"USER_SGREPRC" or "SYSTEM_SGREPRC},
	{ 'P',NULL,"show preprocessed expression, don't execute it." },
	{ 'q',NULL,"supress normal output" },
	/* { 'R',NULL,"recurse into subdirectories" },
 */
	{ 'S',NULL,"stream mode (regions extend across files)"},
	{ 's',NULL,"short output format" },
	{ 'T',NULL,"show statistics about what was done" },
#if HAVE_TIMES
	{ 't',NULL,"show information about time spent"},
#endif
	{ 'V',NULL,"display version information" },
	{ 'v',NULL,"verbose mode. Shows what is going on"},
	{ 'e',"<expression>","execute expression (after preprocessing)" },
	{ 'f',"<file>","read expression from file" },
	{ 'F',"<file>","read list of input files from <file> instead of command line" },
	{ 'g',"<option>","set scanner option:" },
	{ 'O',"<file>","reads output style from file"},
	{ 'o',"<style>","set output style. See man page for details"},
#ifdef USE_EXEC
	{ 'p',"<program>","preprocess expression using external preprocessor" },
#endif
	{ 'w',"<char list>","set the list of characters used to recognize words" },
	{ 'x',"<index file>","use given index file instead of scanner. Implies -S"},
	{ 0,NULL,NULL }
};

int main(int argc, char *argv[])
{
    ParseTreeNode *root;
    struct PHRASE_NODE *p_list;
    FileList *input_files=NULL;
    int end_options;
    struct SgrepStruct sgrep_main_instance;
    
    /* First initialize the sgrep instance */
    memset(&sgrep_main_instance,0,sizeof(sgrep_main_instance));
    sgrep=&sgrep_main_instance;	
    sgrep->do_concat=1;
    sgrep->error_stream=stderr;
    
    sgrep->output_style=SHORT_OUTPUT; /* default is short */
    sgrep->open_failure=OPEN_FAILURE;
    sgrep->print_newline=1;
    sgrep->stdin_temp_file=NULL;	/* not read yet */
    sgrep->print_all=0;
    sgrep->chars_list=NULL;
    sgrep->stream_mode=0;
    
    sgrep->progress_stream=stderr;
    sgrep->scanner_type=SGML_SCANNER;

    /* Check, if we shoud be in indexing mode */
    if ( (argc>0 && strcmp(argv[0],"sgindex")==0) ||
	 (argc>1 && strcmp(argv[1],"-I")==0) ) {
	int r;
	if (strcmp(argv[0],"sgindex")==0) {
	    r=index_main(sgrep,argc-1,argv+1);
	} else {
	    r=index_main(sgrep,argc-2,argv+2);
	}
	check_memory_leaks(sgrep);
	return r;
    }

    /* Mark starting time */
    times(&tps.start);
	
    /* 
     * Process environment options and command line options
     */
    end_options=-1;
    if (environ_options()==SGREP_ERROR || 
	(end_options=get_options(argv+1))==SGREP_ERROR ||
	(last_expression==NULL && end_options>=argc)
	) {
	/* There was error. Print usage information  and exit */
	const struct OptionData *o=option_data;

	if (last_expression==NULL && end_options==argc) {
	    fprintf(stderr,"You have to give an expression line if you don't use -f or -e switch.\n");
	}

	fprintf(stderr,"Usage: sgrep [ -");
	while (o->opt!=0) {
	    if (o->have_param!=NULL) {
		fprintf(stderr," -%c %s",
			o->opt,o->have_param);
	    } else fprintf(stderr,"%c",o->opt);
	    o++;
	}
	fprintf(stderr," ] \'expr\' [<files...>]\n");
	fprintf(stderr,"sgrep -h for help\n");
	exit(2);
    }
	
    /* 
     * Shall we get expression from command line 
     */
    if (last_expression==NULL) {
	struct Expression *e;
	assert(end_options<argc);
	e=sgrep_new(struct Expression);
	e->type=E_TEXT;
	e->expr=sgrep_strdup(argv[end_options]);
	e->next=last_expression;
	last_expression=e;
	end_options++;
    }

    /* 
     * Creating constant lists. They might be needed in the parse() step
     */
    create_constant_lists();
	
    /* 
     * Read, preprocess, parse and optimize
     */
    {
	SgrepString *expression;
	char buf[32768];
	expression=read_expressions(sgrep,last_expression);
	
	if (!expression) {
	    exit(2);
	}
	
	/* 
	 * Invoking preprocessor 
	 */
	if (preprocess(sgrep,expression->s,buf,preprocessor,sizeof(buf))
	    ==SGREP_ERROR) {
	    exit(2);
	}
    
	/* Free the unpreprocessed query */
	delete_string(expression);
	
	/*
	 * If we have show_expr then we show preprocessed expression, and
	 * stop here 
	 */
	if (show_expr) {
	    fprintf(stdout,"%s\n",buf);
	    exit(0);
	}

	/* 
	 * Invoking parser 
	 */
	if ((root=parse_and_optimize(sgrep,buf,&p_list)) == NULL) {
	    sgrep_error(sgrep,"No query to evaluate. Bailing out.\n");
	    exit(2);
	}	
    }

    /* We have done the parsing step */

    times(&tps.parsing);
    

    /* Check for file list in index */
    if (sgrep->index_reader) {
	input_files=index_file_list(sgrep->index_reader);
    }
    
    if (sgrep->index_reader && input_files &&
	(end_options<argc || num_file_list_files)) {
	/* We had file list in index reader. */
	sgrep_error(sgrep,
		    "Warning: -F options and command line file list ignored when using index (-x).\n");
    }

    if (!input_files) {	
	/* 
	 * No index reader or file list in index_reader
	 * Scan input files
	 */
	input_files=check_files(sgrep,argc-end_options,
				argv+end_options,
				num_file_list_files,
				file_list_files);
    }
    
	
	
    /*
     * Evaluation style depends on sgrep->stream_mode 
     */
    if (sgrep->stream_mode)
	run_stream(input_files,root,p_list);
    else
	run_one_by_one(input_files,root,p_list);
    
    free_parse_tree(sgrep,root);
    delete_constant_lists();

    /* 
     * Should we show statistics 
     */
    if (have_stats) show_stats();
	
    /* 
     * Should we show information about time spend 
     */
    if (have_times) show_times();

    /* Free stuff */
    delete_flist(input_files);
    if (sgrep->index_reader) {
	delete_index_reader(sgrep->index_reader);
    }
    if (sgrep->stdin_temp_file) {
	delete_temp_file(sgrep->stdin_temp_file);
    }
    if (stats.region_lists_now>0) {
	fprintf(stderr,"%d region lists still allocated\n",
		stats.region_lists_now);
    }
    if (option_space) sgrep_free(option_space);

    check_memory_leaks(sgrep);
    if (stats.output==0) {
	return 1; /* Empty result list */
    }
    /* non empty result list */
    return 0;
}

#if 0
/*
 * Displays the copyright notice.
 */
void copyright_notice()
{
	int i;
	
	for (i=0;copyright_text[i]!=NULL;i++)
	{
		printf("\t%s\n",copyright_text[i]);
	}
}
#endif

#if HAVE_TIMES
static struct tms t_last;
void CALC_TIME(struct tms *TIME) {
	struct tms t_now;

	times(&t_now);  
	TIME->tms_utime+=t_now.tms_utime-t_last.tms_utime; 
	TIME->tms_stime+=t_now.tms_stime-t_last.tms_stime; 
	t_last=t_now;
}
#endif

/* 
 * Runs sgrep file by file
 */
int run_one_by_one(FileList *files, ParseTreeNode *root, 
		    struct PHRASE_NODE *p_list)
{
	RegionList *result;
	int i;
	int save_print_newline;

#if HAVE_TIMES
	struct tms t_pmatch,t_eval,t_output;

	t_last=tps.parsing;
	t_pmatch.tms_utime=0;
	t_pmatch.tms_stime=0;
	t_eval=t_pmatch;
	t_output=t_pmatch;
#endif
	
#ifdef DEBUG
	fprintf(stderr,"one by one: input_files=%d\n",last_file);
#endif
	save_print_newline=sgrep->print_newline;
	sgrep->print_newline=0;

	for (i=0;i<flist_files(files);i++) {
	    /* fprintf(stderr,"file #%d:%s\n",i,flist_name(files,i)); */

	    /* Got to clear root nodes gc list so that eval won't think
	       that it's already evaluated */
	    root->result=NULL;
	    
	    /* chars list size is the size of file being evaluates */
	    sgrep->chars_list->length=flist_length(files,i);
	    
	    search(sgrep,p_list,files,i,i);
	    CALC_TIME(&t_pmatch);
	    
	    result=eval(sgrep,files,root);
	    stats.output+=LIST_SIZE(result);
	    CALC_TIME(&t_eval);

	    /* FIXME: save_sgrep->print_newline is a horrible historical kludge */
	    if (i==flist_files(files)-1) {
		sgrep->print_newline=save_print_newline;
	    }
	    if ( !display_count && !no_output && (
		LIST_SIZE(result)>0 || sgrep->print_all ))
	    {
		write_region_list(sgrep,stdout,result,files);
	    }
	    
	    /* We free result list,except when we got constant list
	       as result list */
	    if (stats.region_lists_now==stats.constant_lists+1)
	    {
		free_gclist(result);
	    }
	    CALC_TIME(&t_output);
	    
	    /*
	     * Now only constant lists should be left
	     */
	    assert(stats.region_lists_now==stats.constant_lists);
	}
	if ( display_count && !no_output )
	{
	    printf("%d\n",stats.output);
	}
	fflush(stdout);

#if HAVE_TIMES
	tps.acsearch=tps.parsing;
	tps.acsearch.tms_utime+=t_pmatch.tms_utime;
	tps.acsearch.tms_stime+=t_pmatch.tms_stime;
	tps.eval=tps.acsearch;
	tps.eval.tms_utime+=t_eval.tms_utime;
	tps.eval.tms_stime+=t_eval.tms_stime;
	tps.output=tps.eval;
	tps.output.tms_utime+=t_output.tms_utime;
	tps.output.tms_stime+=t_output.tms_stime;
#endif
	
	return SGREP_OK;
}
		
#undef DEBUG
/*
 * Runs sgrep in stream mode
 */
int run_stream(FileList *files, ParseTreeNode *root, struct PHRASE_NODE *p_list)
{
	RegionList *result;
			
	/* Pattern matching on input files */	
#ifdef DEBUG
	fprintf(stderr,"Starting search\n");
#endif
	if (search(sgrep,p_list,files,0,flist_files(files)-1)==SGREP_ERROR) {
	    return SGREP_ERROR;
	}
	times(&tps.acsearch);
	
	/* Evaluate the expression */
#ifdef DEBUG
	fprintf(stderr,"Evaluating.\n");
#endif
	result=eval(sgrep,files,root);
	if (result==NULL) return SGREP_ERROR;

	if (stats.region_lists_now>stats.constant_lists+1) {
	    sgrep_error(sgrep,"Query leaked %d gc lists\n",
			stats.region_lists_now-stats.constant_lists+1);
	}
	times(&tps.eval);
	
	/* Outputting result */
#ifdef DEBUG
	fprintf(stderr,"Output result.\n");
	fflush(stderr);
#endif
	
	stats.output=LIST_SIZE(result);
	/* Should we show the count of matching regions */
	if ( display_count )
	{
		printf("%d\n",LIST_SIZE(result));
	}
	/* We show result list only if there wasn't -c option, and there was
	   something to output */
	if ( !display_count && !no_output && (
			stats.output>0 || sgrep->print_all ))
	    write_region_list(sgrep,stdout,result,files);
	free_gclist(result);
	fflush(stdout);
	times(&tps.output);
	return SGREP_OK;
}

/*
 * Prints help 
 */
void print_help()
{
	const struct OptionData *o;
	
	printf("Usage: sgrep <options> 'region expression' [<files...>]\n");
	printf("If no files are given stdin is used instead.\n");
	printf("Use 'sgrep -I -h' or 'sgindex -h' for help on indexing mode options.\n");
	printf("\noptions are:\n");

	for (o=option_data;o->opt!=0;o++)
	{
		printf("  -%c %-12s %s\n",
			o->opt,
			(o->have_param==NULL) ?
				"":
				o->have_param,
			o->what_does);
		if (o->opt=='g') {
		    print_scanner_help();
		}
	}
	printf("  -- %-12s no more options\n","");
	printf("Options can also be specified with "ENV_OPTIONS" environment variable\n");
	exit(0);
}

/*
 * Creates and initializes the constant lists, start end and chars.
 * They may need to be modified later, because when scanning each
 * file separately end point keeps changing
 */
void create_constant_lists()
{
    
    /* Chars list is optimized and created in a special way */
    sgrep->chars_list=new_region_list(sgrep);
    to_chars(sgrep->chars_list,1,1);
    
    stats.constant_lists+=1;
}

void delete_constant_lists() {
    free_gclist(sgrep->chars_list);
    sgrep->chars_list=NULL;
    stats.constant_lists-=1;
}

/*
 * Catenates expression file to string
 */
int read_expression_file(SgrepString *str, const char *fname) {
    FILE *stream;
    char buf[1024];
    int bytes;
    SGREPDATA(str);

    /* First add a newline, if there isn't one already */	
    if (str->length>0 && str->s[str->length-1]!='\n') {
	string_cat(str,"\n");
    }

    if (fname[0]=='-' && fname[1]==0) {	
	/* Expression is coming from stdin */
	stream=stdin;
	string_cat(str,"#line 1 \"-\"\n");
    } else {
	stream=fopen(fname,"r");
	if (stream==NULL) {    
	    sgrep_error(sgrep,"Expression file '%s' : %s\n",
			fname,strerror(errno));
	    return SGREP_ERROR;
	}
	string_cat(str,"#line 1 \"");
	string_cat(str,fname);
	string_cat(str,"\"\n");
    }

    do {
	bytes=fread(buf,1,sizeof(buf)-1,stream);
	buf[bytes]=0;
	string_cat(str,buf);
    } while (!feof(stream) && !ferror(stream));

    if (ferror(stream)) {
	sgrep_error(sgrep,"Reading file '%s' : %s\n",
		    fname,strerror(errno));	
	if (stream!=stdin) fclose(stream);
	return SGREP_ERROR;
    }
    if (stream!=stdin) fclose(stream);
    return SGREP_OK;
}

/*
 * Reads the expression commands to com_file_buf 
 */
SgrepString *read_expressions(SgrepData *sgrep,
			      struct Expression *expression_list) {
    SgrepString *return_string;

    if (expression_list==NULL) {
	FILE *test_stream=NULL;
	return_string=new_string(sgrep,8192);

	/* Check for USER_SGREPRC */
	if (read_sgreprc && getenv("HOME")) {
	    SgrepString *sgreprc=new_string(sgrep,1024);
	    string_cat(sgreprc,getenv("HOME"));
	    string_cat(sgreprc,"/");
	    string_cat(sgreprc,USER_SGREPRC);
	    test_stream=fopen(sgreprc->s,"r");
	    if (test_stream) {
		/* found USER_SGREPRC */
		if (read_expression_file(return_string,string_to_char(sgreprc))
		    ==SGREP_ERROR) {
		    delete_string(return_string);
		    return_string=NULL;
		}
	    }
	    delete_string(sgreprc);
	}
	
	/* Check for SYSTEM_SGREPRC */
	if (read_sgreprc && !test_stream) {
	    test_stream=fopen(SYSTEM_SGREPRC,"r");
	    if (test_stream) {
		if (read_expression_file(return_string,SYSTEM_SGREPRC)
		    ==SGREP_ERROR) {
		    delete_string(return_string);
		    return_string=NULL;
		}
	    }
	}
	
	if (test_stream) fclose(test_stream);
	return return_string;
    }

    /* Shameless use of recursion */
    return_string=read_expressions(sgrep,expression_list->next);

    if (return_string!=NULL)  {
	switch(expression_list->type){
	case E_FILE:
	    if (read_expression_file(return_string,expression_list->expr)
		==SGREP_ERROR) {
		delete_string(return_string);
		return_string=NULL;
	    }
	    break;
	case E_TEXT:
	    /* First add a newline, if there isn't one already */	
	    if (return_string->length>0 &&
		return_string->s[return_string->length-1]!='\n') {
		string_cat(return_string,"\n");
	    }	    
	    string_cat(return_string,"#line 1 \"\"\n");
	    string_cat(return_string,expression_list->expr);
	    break;
	}
    }
    sgrep_free(expression_list->expr);
    sgrep_free(expression_list);
    return return_string;
}

/*
 * Reads output style from file
 */
void read_style_file(char *fname)
{
	int fd;
	int l,r;
	
	fd=open(fname,O_RDONLY);
	if (fd==-1)
	{
		sgrep_error(sgrep,"open style file %s : %s\n",fname,strerror(errno));
		exit(2);
	}
	l=lseek(fd,0,SEEK_END);
	if (l==-1)
	{
		sgrep_error(sgrep,"lseek style file %s : %s\n",fname,strerror(errno));
		exit(2);
	}
	lseek(fd,0,SEEK_SET);
	sgrep->output_style=(char *)sgrep_malloc(l+1);
	r=read(fd,sgrep->output_style,l);
	if (r==-1)
	{
		sgrep_error(sgrep,"read style file %s : %s\n",fname,strerror(errno));
		exit(2);
	}
	if (r==0)
	{
		sgrep_error(sgrep,"Empty style file %s\n",fname);
		exit(2);
	}
	sgrep->output_style[r]=0;
	close(fd);
}

/*
 * Checks the command line options 
 */
int get_options(char *argv[])
{
	int i,j;
	
	i=1;
	j=1;

	
	while ( *argv!=NULL && *argv[0]=='-' )
	{
		/* option -- means no more options */
		if (strcmp(*argv,"--")==0) return i+1;

		switch((*argv)[j])

		{
		case 'h':
			print_help();
			break;
		case 'V':
			printf("sgrep version %s compiled at %s\n",
				VERSION,__DATE__);
			exit(0);
			break;
		case 'v':
		        sgrep->progress_output=1;
			break;
		case 'T':
			have_stats=1;
			break;
		case 't':
			have_times=1;
			break;
		case 'a':
			sgrep->print_all=1;
			break;
		case 'i':
			sgrep->ignore_case=1;
			break;
		case 'l':
			sgrep->output_style=LONG_OUTPUT;
			sgrep->do_concat=0;
			break;
		case 's':
			sgrep->output_style=SHORT_OUTPUT;
			sgrep->do_concat=1;
			break;
		case 'o':
			sgrep->output_style=get_arg(sgrep,&argv,&i,&j);
			if (!sgrep->output_style) return SGREP_ERROR;
			sgrep->do_concat=0;
			break;
		case 'c':
			display_count=1;
			sgrep->do_concat=0;
			no_output=0;
			break;
		case 'd':
			sgrep->do_concat=0;
			break;
		case 'N':
			sgrep->print_newline=0;
			break;
#if 0
		case 'C':
			copyright_notice();
			exit(0);
			break;
#endif
		case 'f': {
		    char *arg;
		    struct Expression *e;
		    arg=get_arg(sgrep,&argv,&i,&j);
		    if (arg==NULL) return SGREP_ERROR;
		    e=sgrep_new(struct Expression);
		    e->expr=sgrep_strdup(arg);
		    e->type=E_FILE;
		    e->next=last_expression;
		    last_expression=e;
		}
		break;
		case 'F': {
		    char *arg;

		    if (num_file_list_files==MAX_FILE_LIST_FILES) {
			sgrep_error(sgrep,
			    "too many file list files (more than %d -F options given)\n",
			    MAX_FILE_LIST_FILES);
			return SGREP_ERROR;
		    }
		    arg=get_arg(sgrep,&argv,&i,&j);
		    if (!arg) return SGREP_ERROR;
		    file_list_files[num_file_list_files++]=arg;
		    break;
		}
		case 'g': {
		    char *arg;
		    arg=get_arg(sgrep,&argv,&i,&j);
		    if (!arg) return SGREP_ERROR;
		    if (set_scanner_option(sgrep,arg)==SGREP_ERROR) {
			exit(2);
		    }
		    break;
		}
		case 'e': {
		    char *arg;
		    struct Expression *e;

		    arg=get_arg(sgrep,&argv,&i,&j);
		    if (!arg) return SGREP_ERROR;
		    e=sgrep_new(struct Expression);
		    e->expr=sgrep_strdup(arg);
		    e->type=E_TEXT;
		    e->next=last_expression;
		    last_expression=e;
		    break;
		}
		case 'p':
			preprocessor=get_arg(sgrep,&argv,&i,&j);
			if (!preprocessor) return SGREP_ERROR;
			break;
		case 'n':
			read_sgreprc=0;
			break;
		case 'O': {
		    char *arg;
		    arg=get_arg(sgrep,&argv,&i,&j);
		    if (!arg) return SGREP_ERROR;
		    read_style_file(arg);
		    break;
		}
		case 'P':
			show_expr=1;
			break;
		case 'D':
			sgrep->progress_output=1;
			break;
		case 'S':
			sgrep->stream_mode=1;
			break;
		case 'R':
			sgrep->recurse_dirs=1;
			fprintf(stderr,"WARNING -R not working (yet)\n");
			break;			
		case 'q':
			no_output=1;
			break;
		case 'x':
		    sgrep->index_file=get_arg(sgrep,&argv,&i,&j);
		    if (!sgrep->index_file) return SGREP_ERROR;
		    if (sgrep->index_reader) {
			fprintf(stderr,"-x option used twice. Multiple indexes at once is not implemented.\n");
			exit(2); 
		    }
		    sgrep->index_reader=new_index_reader(sgrep,sgrep->index_file);
		    if (sgrep->index_reader==NULL) {
			fprintf(stderr,"Index file unusable. Bailing out.\n");
			exit(2);
		    }
		    sgrep->stream_mode=1;
		    break;
		case 'w':
			sgrep->word_chars=get_arg(sgrep,&argv,&i,&j);
			if (!sgrep->word_chars) return SGREP_ERROR;
			break;
		default:
			fprintf(stderr,"Illegal option -%c\n",(*argv)[j]);
			return -1;
			break;
		}
		if ((*argv)[++j]==0)
		{
			argv++;
			i++;
			j=1;
		}
	}
	return i;
}


/*
 * Shows the statistics ( from stats struct ) 
 */
void show_stats()
{
	fprintf(stderr,
	"Scanned %d files, having total of %dK size finding %d phrases.\n",
		stats.scanned_files,
		stats.scanned_bytes/1024,
		stats.phrases);
	fprintf(stderr,"Operator tree size was %d, optimized %d\n",
		stats.parse_tree_size,
		stats.parse_tree_size-stats.optimized_nodes);
	fprintf(stderr,"Output list size was %d regions.\n",stats.output);		 
	fprintf(stderr,
		"Operations:\n%15s:%-4d%6s:%-4d%5s:%-4d%5s:%-4d%11s:%-4d%3s:%-4d\n",
		"containing",stats.containing,
		"in",stats.in,
		"order",stats.order,
		"or",stats.or_oper,
		"extracting",stats.extracting,
		"quote",stats.quote);
	fprintf(stderr,"%15s:%-4d%6s:%-4d%5s:%-4d%5s:%-4d%11s:%-4d%4s:%-4d\n",
		"not containing",stats.not_containing,
		"not in",stats.not_in,
		"inner",stats.inner,
		"outer",stats.outer,
		"concat",stats.concat,
		"join",stats.join);
	fprintf(stderr,"%15s:%-4d%6s:%-4d\n",
		"equal",stats.equal,
		"not equal",stats.not_equal);
	fprintf(stderr,"%15s:%-4d%6s:%-4d\n",
		"parenting",stats.parenting,
		"childrening",stats.childrening);
	fprintf(stderr," Total %d operations evaluated.\n",stats.operators_evaluated);
#if MEMORY_DEBUG
	fprintf(stderr,"Memory:\n %dK peak memory usage, %d realloc operations\n",
		stats.peak_memory_usage/1024,stats.reallocs);
#endif
	fprintf(stderr," %d gc lists created", stats.region_lists);
  	fprintf(stderr," %d gc blocks used, %d gc blocks allocated.\n",
		stats.gc_nodes,stats.gc_nodes_allocated);
	fprintf(stderr," Longest list size was %d regions.\n",
		stats.longest_list);
	fprintf(stderr,
		"Things done:\n %d %s\n %d %s, %d %s, %d %s\n",
		stats.scans,"gc lists scanned",
		stats.sorts_by_start,"sorts by start point",
		stats.sorts_by_end,"sorts by end point"
		,stats.remove_duplicates,"remove duplicates"
		);
#ifdef OPTIMIZE_SORTS
	fprintf(stderr," %d sorts optimized\n",stats.sorts_optimized);
#endif
	if (stats.optimized_phrases)
	{
		fprintf(stderr," %d same phrases\n",stats.optimized_phrases);
	}
}		






#if HAVE_TIMES
/*
 * Calculates the difference between two time
 * and returns it 
 */
float calc_time(clock_t b,clock_t e)
{
	static long clktck=0;
	
	if (clktck==0) clktck=sysconf(_SC_CLK_TCK);
	if (clktck<0) return 0;
	
	return ((float)(e-b)/(float)clktck);
}
#endif

#if HAVE_TIMES
/* 
 * Prints a nice looking line of time information with label 
 */
void print_time(char *label,struct tms *b,struct tms *e)
{
	float sys,usr;
	
	usr=calc_time(b->tms_utime,e->tms_utime);
	sys=calc_time(b->tms_stime,e->tms_stime);
	fprintf(stderr,"  %-18s%6.2fs %6.2fs %6.2fs\n",label,usr,sys,usr+sys);;
}
#endif

/* 
 * Prints information about time used to stderr
 */

void show_times()
{
#if HAVE_TIMES
    fprintf(stderr,"%-18s%8s%8s%8s\n",
	    "sgrep time usage","usr","sys","total");
    print_time("parsing",&tps.start,&tps.parsing);
    print_time("acsearch",&tps.parsing,&tps.acsearch);
    print_time("evaluating",&tps.acsearch,&tps.eval);
    print_time("output",&tps.eval,&tps.output);
    fprintf(stderr,"  -----------------------------------------\n");
    print_time("total",&tps.start,&tps.output);
    if (tps.output.tms_cutime>0)
    {
	fprintf(stderr,"\n");
	print_time("preprocessor",
		   (struct tms *)&tps.start.tms_cutime,
		   (struct tms *)&tps.output.tms_cutime);
    }
#else
    fprintf(stderr,"No time usage information available on this platform\n");
#endif
}

/*
 * Reads the options from environ variable ENV_OPTIONS
 */
int environ_options()
{
    char *av[100];
    int i=0;
    int j=0;
    char *o;
	
    if (getenv(ENV_OPTIONS)==NULL) return 0;
    
    o=(char *)sgrep_malloc(strlen(getenv(ENV_OPTIONS)+1));
    option_space=o;
    strcpy(o,getenv(ENV_OPTIONS));
    
    do {
	while( o[i]==' ' ) 
	{
	    o[i++]=0;
	}
	if (!o[i]) break;
	av[j++]=&o[i];
	if (j==100)
	{
	    sgrep_error(sgrep,"Too complex "ENV_OPTIONS"\n");
	    exit(2);
	}
	while( o[i]!=' ' && o[i]!=0 ) i++;
    } while (o[i]);
    av[j]=NULL;
    
#ifdef DEBUG
    fprintf(stderr,"Environment options: ");
    for (i=0;av[i]!=NULL;i++)
    {
	fprintf(stderr,"'%s' ",av[i]);
    }
    fprintf(stderr,"\n");
#endif
    i=get_options(av);
    if (i==-1)
    {
	sgrep_error(sgrep,"Invalid "ENV_OPTIONS" ("ENV_OPTIONS"=%s)\n",getenv(ENV_OPTIONS));
	return SGREP_ERROR;
    }
    if (i<=j)
    {
	sgrep_error(sgrep,"No files or expressions allowed in "ENV_OPTIONS"\n");
	return SGREP_ERROR;
    }
    return 0;
}

