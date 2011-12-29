/*
	System: Structured text retrieval tool sgrep.
	Module: preproc.c
	Author: Pekka Kilpeläinen & Jani Jaakkola
	Description: Handles preprocessing of expressions using some
		     external macro expanding program. ( like m4 or cpp )
		     used through function preprocess()
	Version history: Original version February 1995 by JJ & PK
	Copyright: University of Helsinki, Dept. of Computer Science
*/

/*
 * NOTE: Inbuild preprocessed has been planned but implemented. It's not
 *       clear whether it would be useful.
 */
  
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <limits.h>
#include <errno.h>

#define SGREP_LIBRARY
#include "sgrep.h"


#if HAVE_UNISTD_H
# include <unistd.h>
#endif

#ifndef PIPE_BUF
 #define PIPE_BUF 512
#endif


/*
 * preprocess preprocesses given input string using given preprocessor.
 * maxsize specifies maximum size of output string.
 * if processor==NULL inbuilt default processor is used instead
 * if processor=="-" no preprocessing is done
 * returns size of output_str
 */

#ifdef UNIX_PREPROCESS
#include <signal.h>
#include <sys/types.h>
#include <sys/time.h>
#include <sys/wait.h>
int preprocess( char *input_str, char *output_str, char *processor, int maxsize )
{
#ifdef USE_EXEC
	int pfd1[2];
	int pfd2[2];
	int i,j,r,s;
	pid_t p; /* Thanks to Han Holl */
	int t;
	int status;
	fd_set rfs;
	fd_set wfs;
#endif
	
#ifdef DEBUG
	fprintf(stderr,"Preprocess string: %s\n",input_str);
#endif

	if ( processor==NULL )
	{
		fprintf(stderr,"Inbuilt preprocessor not implemented yet.\n");
		processor="-";
	}
	
	if ( strcmp(processor,"-")==0 )
	{
		/* No processing, just return copy of input_str */
#ifdef DEBUG
		fprintf(stderr,"preprocessor: just copy to output\n");
#endif

#ifdef assert
		assert((int)strlen(input_str)<maxsize);
#endif
		strcpy(output_str,input_str);
		return 0;
	}
	
#ifndef USE_EXEC
	fprintf(stderr,"Spawning external preprocessors not compiled in.\n");
	exit(2);
#endif

#ifdef USE_EXEC

#ifdef DEBUG
	fprintf(stderr,"Spawning preprocessor '%s'\n",processor);
#endif
	if ( pipe(pfd1)!=0 || pipe(pfd2)!=0 )
	{
		perror("pipe");
		exit(2);
	}
	fflush(stderr);
	fflush(stdout);
	if ( (p=fork())==-1 )
	{
		perror("fork");
		exit(2);
	}
	if (p==0)
	{
		if (dup2(pfd1[0],0)==-1) exit(127);
		if (dup2(pfd2[1],1)==-1) exit(127);
		close(pfd1[1]);
		close(pfd1[0]);
		close(pfd2[1]);
		close(pfd2[0]);
#ifdef DEBUG
		fprintf(stderr,"child: execl(%s,%s,%s,%s,NULL)\n",EXEC_SHELL,processor);
		fflush(stderr);
#endif
		execlp(processor,processor,NULL);
		perror("exec");
		exit(127);
	}
	close(pfd1[0]);
	close(pfd2[1]);
	r=-2;
	i=0;
	j=0;
	while ( r!=0 )
	{	
		FD_ZERO(&rfs);
		FD_ZERO(&wfs);
		FD_SET(pfd2[0],&rfs);
		if ( input_str[i] ) 
			FD_SET(pfd1[1],&wfs);

		s=select( (pfd1[1]>pfd2[0]) ? pfd1[1]+1:pfd2[0]+1 ,&rfs,&wfs,NULL,NULL);
#ifdef DEBUG
		fprintf(stderr,"write %d read %d\r",i,j);
		fflush(stderr);
#endif
		if (s==-1 && errno!=EINTR)
		{
			kill(p,SIGTERM);
			perror("select");
			exit(2);
		}
		if ( s>0 && FD_ISSET(pfd1[1],&wfs) && input_str[i])
		{
			t=( (PIPE_BUF < (int)strlen(&input_str[i])) ? 
				PIPE_BUF:strlen(&input_str[i]) );
			if ( (t=write(pfd1[1],&input_str[i],t))==-1 )
			{
				kill(p,SIGTERM);
				perror("write to child");
				exit(2);
			}
			i+=t;
			if (!input_str[i]) 
				close(pfd1[1]);
		}
		if ( s>0 && FD_ISSET(pfd2[0],&rfs) )
		{
			r=read(pfd2[0],&output_str[j],maxsize-j);
			if ( r<0 )
			{
				kill(p,SIGTERM);
				perror("read from child");
				exit(2);
			}
			j+=r;
			if ( j>=maxsize )
			{
				kill(p,SIGTERM);
				fprintf(stderr,"%s (>%d)\n",
	"Preprocessor output exceeded maximum output size",maxsize);
				exit(2);
			}
			output_str[j]=0;	
		}	
	}	
	if (input_str[i])
	{
		close(pfd1[1]);
		/* Preprocessor didn't read all it's input.
		   should it be terminated ? */	
		/* kill(p,SIGTERM); */
		/* Should there be a warning ? */
#ifdef DEBUG		
		fprintf(stderr,"Warning: Preprocessor didn't read all it's input\n");
#endif
		/* Should we stop? I think not. */
                /* exit(2); */
	}
	wait(&status);
	if ( !WIFEXITED(status) )
	{
		fprintf(stderr,"Preprocessor died abnormally\n");
		exit(2);
	}
	if ( WEXITSTATUS(status)==127 )
	{
		fprintf(stderr,"exec failed\n");
		exit(2);
	}
	if ( WEXITSTATUS(status)!=0 )
	{
		fprintf(stderr,"Preprocessor returned exit status %d\n",
			WEXITSTATUS(status));
		exit(2);
	}
#ifdef DEBUG
	fprintf(stderr,"Preprocessor output:%s",output_str);
#endif	
	return strlen(output_str);
#endif
}

/* ifdef UNIX_PREPROCESS */
#else
	
/*
 * Here is a version of preprocess, which does not use pipe(),fork(),wait() and
 * exec(), and therefore is (but only slightly, because i still need dup(),
 * dup2() and fileno()) slightly more portable than
 * the previous preprocess().
 * (This thing is here, because there seems to be bugs in implementation
 * of pipes in cygwin32 _beta_ 19.1. ) */
int preprocess(SgrepData *sgrep, char *input_str, 
	       char *output_str, char *processor, int maxsize ) {
    TempFile *temp_file1,*temp_file2;
    FILE *tmpf1,*tmpf2;
    int tmp_stdinfd, tmp_stdoutfd;
    int out_bytes=0;
    int e;

    if (strcmp(processor,"-")==0) {
        strncpy(output_str,input_str,maxsize);
        return strlen(output_str);
    }
    temp_file1=temp_file2=NULL;
    tmpf1=tmpf2=NULL;
    tmp_stdinfd=tmp_stdoutfd=-1;
    
    /* For some reason, unlinking temp_file2 causes preprocessor output
     * to be lost. */
    if ( (temp_file1=create_temp_file(sgrep))==NULL ||
	 (temp_file2=create_temp_file(sgrep))==NULL) {
	sgrep_error(sgrep,"Failed to create tmpfile for preprocessing\n");
	goto error;
    }
    tmpf1=temp_file_stream(temp_file1);
    tmpf2=temp_file_stream(temp_file2);    
    if (fputs(input_str,tmpf1)==EOF ||
	fseek(tmpf1,0,SEEK_SET)!=0 ||
	fflush(tmpf1)==EOF ||
	ferror(tmpf1)) {
	sgrep_error(sgrep,"Failed to write preprocessor tmpfile: %s\n",
		    strerror(errno));
	goto error;
    }
    
    /* Yes, this should work if there is no stdin and stdout */
    if ( (tmp_stdinfd=dup(0))==-1 || 
	 (tmp_stdoutfd=dup(1))==-1) {
	sgrep_error(sgrep,"dup: %s\n",strerror(errno));
	goto error;
    }

    /* We have already at least two open files dont we? */
    assert(tmp_stdinfd>=2 && tmp_stdoutfd>=2);
    if (dup2(fileno(tmpf1),0)<0 || dup2(fileno(tmpf2),1)<0) {
	sgrep_error(sgrep,"dup2:%s",strerror(errno));
	goto error;
	
    }
    if ( (e=system(processor))<0) {
        sgrep_error(sgrep,"system(\"%s\"):%s\n",
		    processor,strerror(errno));
	goto error;
    }
    if ( e!=0 ) {
        sgrep_error(sgrep,"system(\"%s\") returned non zero exit status (%d).\n",
			       processor, e);
    }
    if (dup2(tmp_stdinfd,0)<0) {
	sgrep_error(sgrep,"dup2(stdin,0):%s",strerror(errno));
	goto error;
    }
    close(tmp_stdinfd);
    tmp_stdinfd=-1;
    if (dup2(tmp_stdoutfd,1)<0) {
	sgrep_error(sgrep,"dup2(stdout,1):%s",strerror(errno));
	goto error;
    }
    close(tmp_stdoutfd);
    tmp_stdoutfd=-1;
    /* We don't need the first tmpfile anymore */
    delete_temp_file(temp_file1);
    tmpf1=NULL;

    
    if (
	fseek(tmpf2,0,SEEK_END)!=0 ||
	fseek(tmpf2,0,SEEK_SET)!=0 ||
	(out_bytes=fread(output_str,1,maxsize,tmpf2))<0 || /* Shouldn't happen actually.. */
	ferror(tmpf2)) {
	sgrep_error(sgrep,"Error reading preprocessor output:%s",strerror(errno));
	goto error;
    }
    if (out_bytes>=maxsize) {
	sgrep_error(sgrep,"Preprocessor output too long (>%d bytes)\n",
		maxsize);
	out_bytes=maxsize-1;
    }
    delete_temp_file(temp_file2);
    tmpf2=NULL;
    output_str[out_bytes]=0;
    if (out_bytes==0) {
	sgrep_error(sgrep,"Preprocessor returned empty file\n");
	return SGREP_ERROR;
    }
    return out_bytes;

 error:
    if (temp_file1!=NULL) delete_temp_file(temp_file1);
    if (temp_file2!=NULL) delete_temp_file(temp_file2);
    if (tmp_stdinfd>0) {
	dup2(tmp_stdinfd,0);
	close(tmp_stdinfd);
    }
    if (tmp_stdoutfd>0) {
	dup2(tmp_stdoutfd,0);
	close(tmp_stdoutfd);
    }
    output_str[0]=0;
    return SGREP_ERROR;
}
#endif
