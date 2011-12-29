#include "sgrep.h"

/*
 * List & description of options accepted by sgindex 
 */
struct index_opt_data {
	char opt;
	char *have_param;
	char *what_does;
} index_options[]= {
#if 0
    { 'C',NULL,"display copyright notice" },
#endif
    { 'h',NULL,"help (means this text)" },
    { 'i',NULL,"fold all words to lower case when indexing" },
    /* { 'R',NULL,"recurse into subdirectories" }, */ 
    { 'T',NULL,"show statistics about created index files" },
    { 'V',NULL,"display version information" },
    { 'v',NULL,"verbose mode. Shows what is going on"},
    { 'c',"<index file>", "create new index file" },
    { 'F',"<file>","read list of input files from <file> instead of command line" },
    { 'g',"<option>","set scanner option:" },
    { 'l',"<limit>", "make a list of possible stopwords" },
    { 'L',"<stop file>","write possible stopwords to file" },
    { 'S',"<stop file>","read stop word list from file" },
    { 'm',"<megabytes>", "main memory available for indexing in megabytes" },
    { 'w',"<char list>","set the list of characters used to recognize words" },
    { 'x',"<index file>","query existing index file"},
    { 'q',"<query>","Only can query terms" },
    { 0,NULL,NULL }
};

void index_usage(SgrepData *sgrep) {
    int i;
    sgrep_error(sgrep,"Usage: (sgindex | sgrep -I) [ -");
    for(i=0;index_options[i].opt!=0;i++) {
	if (index_options[i].have_param!=NULL)
	{
	    sgrep_error(sgrep," -%c %s",
		    index_options[i].opt,
		    index_options[i].have_param);
	} else sgrep_error(sgrep,"%c",index_options[i].opt);
    }
    sgrep_error(sgrep," ] [<files...>]\n");
    sgrep_error(sgrep,"sgindex -h for help\n");
}

/*
 * Prints help 
 */
void print_index_help()
{
	int i;
	
	printf("Usage: (sgindex | sgrep -I) <options> <files...>\n");
	printf("Use 'sgrep -h' for help on query mode options.\n");
	printf("\nIndexing mode options are:\n");
	for (i=0;index_options[i].opt!=0;i++)
	{
		printf("  -%c %-13s%s\n",
			index_options[i].opt,
			(index_options[i].have_param==NULL) ?
				(char *)"":
				index_options[i].have_param,
			index_options[i].what_does);
		if (index_options[i].opt=='g') {
		    print_scanner_help();
		}		
	}
	printf("\t--\t\tno more options\n");
}

int parse_index_options(IndexOptions *o, char **argv) {
	int i,j;
	SGREPDATA(o);
	
	i=0;
	j=1;

	
	while ( *argv!=NULL && *argv[0]=='-' )
	{
		/* option -- means no more options */
		if (strcmp(*argv,"--")==0) return i+1;

		switch((*argv)[j])
		{
		case 'g': {
		        char *arg;
			arg=get_arg(sgrep,&argv,&i,&j);
			if ((!arg) || 
			    set_scanner_option(o->sgrep,arg)==SGREP_ERROR) {
			    return SGREP_ERROR;
			}
			break;
		}
		case 'h':
			print_index_help();
			o->index_mode=IM_DONE;
			break;
		case 'i':
			o->sgrep->ignore_case=1;
			break;
		case 'l': {
			char *endptr;
		        char *arg=get_arg(sgrep,&argv,&i,&j);
			if (!arg) return SGREP_ERROR;
			o->stop_word_limit=strtol(arg,&endptr,10);
			if (o->stop_word_limit<0 || *endptr!=0) {
			    sgrep_error(sgrep,"Invalid stop word limit '%s'\n",
				    arg);
			    return SGREP_ERROR;
			}
			break;
		}
		case 'm': {
			char *endptr;
		        char *arg=get_arg(sgrep,&argv,&i,&j);
			if (!arg) return SGREP_ERROR;
			o->available_memory=strtol(arg,&endptr,10)*1024*1024;
			if (o->available_memory<0 || *endptr!=0) {
			    sgrep_error(sgrep,"Invalid memory size '%s'\n",
				    arg);
			    return SGREP_ERROR;
			}
			break;
		}		    
		case 'L':
		        o->output_stop_word_file=get_arg(sgrep,&argv,&i,&j);
			if (!o->output_stop_word_file) return SGREP_ERROR;
			break;
		case 'S':
			o->input_stop_word_file=get_arg(sgrep,&argv,&i,&j);
			if (!o->input_stop_word_file) return SGREP_ERROR;
			break;
		case 'V':
			printf("sgindex version %s compiled at %s\n",
				VERSION,__DATE__);
			o->index_mode=IM_DONE;
			break;
		case 'v':
		        o->sgrep->progress_output=1;
			break;
		case 'T':
			o->index_stats=1;
			break;
#if 0
		case 'C':
			copyright_notice();
			o->index_mode=IM_DONE;
			break;
#endif
		case 'R':
			o->sgrep->recurse_dirs=1;
			sgrep_error(sgrep,"WARNING -R not working (yet)\n");
			break;
		case 'c':
		    o->file_name=get_arg(sgrep,&argv,&i,&j);
		    if (o->file_name==NULL) return SGREP_ERROR;
		    o->index_mode=IM_CREATE;
		    break;
		case 'x':
		    o->sgrep->index_file=get_arg(sgrep,&argv,&i,&j);
		    if (o->sgrep->index_file==NULL) return SGREP_ERROR;
		    break;
		case 'q': {
		    const char *arg=get_arg(sgrep,&argv,&i,&j);
		    if (strcmp(arg,"terms")==0) {
			o->index_mode=IM_TERMS;
		    } else {
			sgrep_error(sgrep,"Don't know how to query '%s'\n",
				    arg);
			return SGREP_ERROR;
		    }	
		    break;
		}		    
		case 'F': {
		    char *arg;
		    arg=get_arg(sgrep,&argv,&i,&j);
		    if (arg==NULL) return SGREP_ERROR;
		    if (o->file_list_files==NULL) {
			o->file_list_files=new_flist(sgrep);
		    }
		    flist_add(o->file_list_files,arg);
		    break;
		}
		case 'w':
			o->sgrep->word_chars=get_arg(sgrep,&argv,&i,&j);
			if (!o->sgrep->word_chars) return SGREP_ERROR;
			break;
		default:
			sgrep_error(sgrep,"Illegal option -%c\n",(*argv)[j]);
			return SGREP_ERROR;
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

int index_main(SgrepData *sgrep,int argc, char *argv[]) {
    int end_options;
    IndexOptions options;
    FileList *file_list=NULL;

    set_default_index_options(sgrep,&options);
    /* 
     * Get the command line options 
     */
    end_options=parse_index_options(&options,argv);

    if (end_options==SGREP_ERROR) {
	/* There was error. Display usage information */
	index_usage(sgrep);
	goto error;
    }

    switch(options.index_mode) {
    case IM_CREATE: {
	if (argc==end_options && options.file_list_files==NULL) {
	    sgrep_error(sgrep,"Can't read input from stdin when indexing.\n");
	    sgrep_error(sgrep," Use filename '-' to force indexing from stdin.\n");
	    goto error;
	}
	if (argc>end_options) {
	    file_list=check_files(sgrep,argc-end_options,argv+end_options,
				  0,NULL);
	}
	options.file_list=file_list;
	if (create_index(&options)==SGREP_ERROR) {
	    goto error;
	}
	break;
    }
    case IM_TERMS: {
	if (index_query(&options,argc-end_options,argv+end_options)
	    ==SGREP_ERROR) {
	    return 2;
	} else {
	    return 0;
	}
    }
    case IM_DONE:
	return 0;	
    case IM_NONE:	
    default:
	sgrep_error(sgrep,"sgindex: You have to give one of -c, -C -h\n");
	index_usage(sgrep);
	goto error;
    }
    if (file_list) delete_flist(file_list);
    if (options.file_list_files) delete_flist(options.file_list_files);
    return 0;

 error:
    if (file_list) delete_flist(file_list);
    if (options.file_list_files) delete_flist(options.file_list_files);
    return 2;
}
