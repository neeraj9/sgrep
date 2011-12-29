/*
	System: Structured text retrieval tool sgrep.
	Module: eval.c
	Author: Pekka Kilpeläinen & Jani Jaakkola
	Description: Handles the evaluation of sgrep expressions, thus
		     implementing the actual semantics of sgrep language.
		     used through eval() function
	Version history: Original version February 1995 by JJ & PK
	Copyright: University of Helsinki, Dept. of Compter Science
*/

#include <string.h>

#define SGREP_LIBRARY
#include "sgrep.h"

#ifdef OPTIMIZE_SORTS
/* Define this if you want always test that nest optimization works */
#define ASSERT_NESTS
#endif

/* Check for proper containment */

#define contains(r1,r2) \
	(((r1).start<(r2).start && (r1).end>=(r2).end) || \
	((r1).start<=(r2).start && (r1).end>(r2).end))

/*
 * Sometimes regions need to be stacked or queued
 */
#define DEFAULT_STACK_SIZE 1024

typedef struct {
    struct SgrepStruct *sgrep;
    const FileList *files;
    Region *tmp_stack;
    int tmp_stack_size;
} Evaluator;

RegionList *recursive_eval(Evaluator *,ParseTreeNode *root);
RegionList *eval_operator(Evaluator *,ParseTreeNode *root);
RegionList *or(RegionList *,RegionList *);
RegionList *nest_order(Evaluator *, RegionList *,RegionList *,int);
RegionList *quote(RegionList *,RegionList *,int);
RegionList *in(RegionList *,RegionList *,int);
RegionList *containing(Evaluator *,RegionList *,RegionList *,int);
RegionList *extracting(RegionList *,RegionList *);
RegionList *outer(RegionList *);
RegionList *inner(Evaluator*, RegionList *);
RegionList *concat(RegionList *);
RegionList *join(Evaluator *evaluator,RegionList *,int number);
RegionList *first(RegionList *, int number);
RegionList *last(RegionList *, int number);
RegionList *first_bytes(RegionList *,int number);
RegionList *last_bytes(RegionList *,int number);
RegionList *equal(RegionList *,RegionList *,int);
RegionList *parenting(Evaluator *,RegionList *l, RegionList *r);
RegionList *childrening(RegionList *l, RegionList *r);
RegionList *eval_near(RegionList *l, RegionList *r,int num);
RegionList *near_before(RegionList *l, RegionList *r,int num);

int free_tree_node(ParseTreeNode *node);

RegionList *eval(struct SgrepStruct *sgrep,
		     const FileList *file_list,
		     ParseTreeNode *root) {
    RegionList *r;
    Evaluator evaluator;

    evaluator.sgrep=sgrep;
    evaluator.files=file_list;
    evaluator.tmp_stack_size=DEFAULT_STACK_SIZE;
    evaluator.tmp_stack=(Region *)sgrep_malloc(DEFAULT_STACK_SIZE*
	sizeof(Region));
    r=recursive_eval(&evaluator,root);
    if (evaluator.tmp_stack) sgrep_free(evaluator.tmp_stack);
    return r;
}

/*
 * Recursively evaluates parse tree using operation functions
 * root points the root node of parse tree
 */
RegionList *recursive_eval(Evaluator *evaluator,ParseTreeNode *root)
{	
#ifdef DEBUG
	static int depth=0;
	int i;
#endif
	RegionList *a;
	SGREPDATA(evaluator);
	a=root->result;

#ifdef DEBUG
	depth++;
	for(i=0;i<depth;i++) fputc(' ',stderr);
	fprintf(stderr,"Evaluating oper %s l_label=%d r_label=%d\n",
		give_oper_name(root->oper),root->label_left,root->label_right);
#endif
	assert(root->oper!=INVALID);

	/* If this is a leaf node, we just use leafs gc list */
	if ( a==NULL && root->oper==PHRASE )
	{
	    /* Check for lazy evaluation mode */
	    if (sgrep->index_file && root->leaf->regions==NULL) {
		assert(root->leaf->phrase!=NULL);
		assert(sgrep->index_reader);
		
		if (root->leaf->phrase->s[0]=='#') {
		    /* Builtin, can't be found from index */
		    const char *s=string_to_char(root->leaf->phrase);
		    RegionList *list=new_region_list(sgrep);
		    root->leaf->regions=list;
		    if (strcmp(s,"#start")==0) {
			int start=flist_start(evaluator->files,0);
			add_region(list,start,start);
		    } else if (strcmp(s,"#end")==0) {
			int end=flist_total(evaluator->files)-1;
			add_region(list,end,end);
		    } else {
			sgrep_error(sgrep,
				    "Don't know how to handle phrase %s\n",
				    s);
		    }				    
		} else {
		    root->leaf->regions=index_lookup(
			sgrep->index_reader,
			root->leaf->phrase->s);
		}
	    }
	    assert(root->leaf->regions!=NULL);
	    
	    a=root->leaf->regions;
	    root->leaf->regions=NULL;
	    a->refcount=root->refcount;
#ifdef DEBUG
	    for(i=0;i<depth;i++) fputc(' ',stderr);
	    fprintf(stderr,"Using phrase list %s\n",root->leaf->phrase->s);
#endif
	}

	/* If gc_list is still NULL, it means that it hasn't been 
	 * evaluated yet */
	if ( a==NULL )
	{
	    /* Eval it now */

	    a=eval_operator(evaluator,root);
	    a->refcount=root->refcount;
	    /* We free subtrees unneeded gclists */
	    if (free_tree_node(root->left))
	    {
#ifdef DEBUG
		for(i=0;i<depth;i++) putc(' ',stderr);
		fprintf(stderr,"label %d freed (left)\n",root->label_left);
#endif
	    }
	    if (free_tree_node(root->right))
	    {
#ifdef DEBUG
		for(i=0;i<depth;i++) putc(' ',stderr);
		fprintf(stderr,"label %d freed (right)\n",root->label_right);
#endif
	    }
	}
#ifdef DEBUG
	else
	{
		for(i=0;i<depth;i++) fputc(' ',stderr);
		fprintf(stderr,"Using already known list\n");
	}
#endif		
	
	/* Keeps track of longest used gc list */
	if (LIST_SIZE(a)>stats.longest_list)
		stats.longest_list=LIST_SIZE(a);
#ifdef ASSERT_NESTS
	/* We check that if list isn't marked as nested, it really isn't */
	if (!a->nested)
	{
		Region reg1,reg2;
		ListIterator p;
		
		start_region_search(a,&p);
		get_region(&p,&reg1);
		get_region(&p,&reg2);
		while (reg2.start!=-1)
		{
			assert(reg1.end<reg2.end);
			reg1=reg2;
			get_region(&p,&reg2);
		}
	}
#endif	

	root->result=a;	

#ifdef DEBUG
	for(i=0;i<depth;i++) fputc(' ',stderr);
	fprintf(stderr,"eval done\n");
	depth--;
#endif
	return a;
}

/*
 * Handles the actual evaluation of some operation
 */
RegionList *eval_operator(Evaluator *evaluator,ParseTreeNode *root)
{
    RegionList *a,*l,*r;

    a=NULL;
    assert(root->left!=NULL);

	
    /* Evaluate left and right subtrees first */
    l=recursive_eval(evaluator,root->left);
    /* Functions don't have right subtree. */
    if (root->right==NULL) r=NULL;
    else r=recursive_eval(evaluator,root->right);
    
    /* Statistics */
    evaluator->sgrep->statistics.operators_evaluated++;

    /* Find the correct evaluation function */
    switch (root->oper) {
    case OR:
	a=or(l,r);
	break;
    case ORDERED:
    case L_ORDERED:
    case R_ORDERED:
    case LR_ORDERED:
	a=nest_order(evaluator,l,r,root->oper);
	break;
    case QUOTE:
    case L_QUOTE:
    case R_QUOTE:
    case LR_QUOTE:
	a=quote(l,r,root->oper);
	break;
    case IN:
	a=in(l,r,0);
	break;
    case NOT_IN:
	a=in(l,r,1);
	break;
    case CONTAINING:
	a=containing(evaluator,l,r,0);
	break;
    case NOT_CONTAINING:
	a=containing(evaluator,l,r,1);
	break;
/* Start PK Febr 95 */
    case EQUAL:
	a=equal(l,r,0);
	break;
    case NOT_EQUAL:
	a=equal(l,r,1);
	break;
/* End PK Febr 95 */
    case PARENTING:
	a=parenting(evaluator,l,r);
	break;
    case CHILDRENING:
	a=childrening(l,r);
	break;
    case OUTER:
	a=outer(l);
	break;
    case INNER:
	a=inner(evaluator,l);
	break;
    case EXTRACTING:
	a=extracting(l,r);
	break;
    case CONCAT:
	a=concat(l);
	break;
    case JOIN:
	a=join(evaluator,l,root->number);
	break;
    case FIRST:
	a=first(l,root->number);
	break;
    case LAST:
	a=last(l,root->number);
	break;
    case FIRST_BYTES:
	a=first_bytes(l,root->number);
	break;
    case LAST_BYTES:
	a=last_bytes(l,root->number);
	break;
    case NEAR:
	a=eval_near(l,r,root->number);
	break;
    case NEAR_BEFORE:
	a=near_before(l,r,root->number);
	break;
    default:
	sgrep_error(evaluator->sgrep, 
		    "Unknown operator in parse tree (%d)\n",
		    root->oper);
	assert(0 && "Unknown operator in parse tree");
	break;
    }
	
    return a;
}

/*
 * Decrements tree nodes reference counter, and frees nodes gc list if
 * counter comes down to 0. Returns 1 if something was freed, 0
 * otherwise
 */
int free_tree_node(ParseTreeNode *node)
{
    if (node==NULL) return 0; /* This was a leaf or function node */ 
  
    if (node->result!=NULL && node->result->refcount!=-1) {
	node->result->refcount--;
	assert(node->result->refcount>=0); 
	if (node->result->refcount==0) {
	    free_gclist(node->result);
	    node->result=NULL;
	    return 1;
	}
    }
    return 0;
}

#ifdef PROGRESS_REPORTS
/*
 * Shows a progress report on stderr
 */
void report_progress(char *line,int size, int now)
{
	fprintf(stderr,"%s %d%% done%s\r",
		line,(100*now)/size,"                  ");
	fflush(stderr);
}
#endif

/*
 * Gives first region from two gc_lists, eliminating same regions.
 */
Region first_of(ListIterator *lp,ListIterator *rp)
{
	Region l_reg,r_reg;
	
	/* quite straightforward limiting of two gc lists.
	   same regions are concatanated */	
	get_region(lp,&l_reg);
	get_region(rp,&r_reg);
	if (r_reg.start!=-1 && l_reg.start!=-1)
	{
		if (l_reg.start<r_reg.start)
		{
			prev_region(rp,&r_reg);
			return l_reg;
		} else if (l_reg.start>r_reg.start)
		{
			prev_region(lp,&l_reg);
			return r_reg;
		} else if (l_reg.end<r_reg.end)
		{
			prev_region(rp,&r_reg);
			return l_reg;
		} else if (l_reg.end>r_reg.end)
		{
			prev_region(lp,&l_reg);
			return r_reg;
		} else 
		{
			return r_reg;
		}
	}
	if (r_reg.start!=-1) return r_reg;
	if (l_reg.start!=-1) return l_reg;
	/* Both lists were empty, we return (-1,-1) */
	return r_reg;
}

/*
 * Handles or operation
 */
RegionList *or(RegionList *l,RegionList *r)
{
	ListIterator lp,rp;
	RegionList *a;
	Region tmp;
#ifdef OPTIMIZE_SORTS
	Region prev;
#endif	
#ifdef PROGRESS_REPORTS
	char *oper_name;
	int prog;int prog_start;
#endif
	SGREPDATA(l);

#ifdef DEBUG
	fprintf(stderr,"or called\n");
#endif
	stats.or_oper++;
	a=new_region_list(sgrep);
#ifdef OPTIMIZE_SORTS
	prev.start=-1;
	prev.end=-1;
#endif
	start_region_search(l,&lp);
	start_region_search(r,&rp);

#ifdef PROGRESS_REPORTS
	prog_start=LIST_SIZE(r)+LIST_SIZE(l);
	prog=0;
	oper_name="or";
#endif

	for(tmp=first_of(&lp,&rp);tmp.start!=-1;tmp=first_of(&lp,&rp))
	{
#ifdef OPTIMIZE_SORTS
		if ( tmp.end<=prev.end )
		{
			/* We had nesting */
			a->nested=1;
		}
#endif
		add_region(a,tmp.start,tmp.end);
#ifdef OPTIMIZE_SORTS
		prev=tmp;
#endif
	}
	return a;
}
	
/* 
 * Handles ordering which produces possibly nesting gc-lists. 
 */
RegionList *nest_order(Evaluator *evaluator, 
			   RegionList *l,RegionList *r,int type)
{
    ListIterator lp,rp;
    RegionList *a;
    Region r_reg,l_reg;              
    int nest_depth=0;
    int nestings;
    int s,e;
    SGREPDATA(evaluator);
#ifdef PROGRESS_REPORTS
    char *oper_name;
    int prog;int prog_start;
#endif

#ifdef DEBUG
    fprintf(stderr,"nest_order called\n");
#endif
    start_region_search(r,&rp);
    
    stats.order++;
    a=new_region_list(sgrep);
    a->nested=l->nested || r->nested;
#ifdef DEBUG
    if (a->nested) fprintf(stderr,"inherited nesting\n");
#endif

#ifdef PROGRESS_REPORTS
    prog_start=LIST_SIZE(r);
    prog=0;
    switch (type) {
    case L_ORDERED:
	oper_name="_.";
	break;
    case R_ORDERED:
	oper_name="._";
	break;
    case LR_ORDERED:
	oper_name="__";
	break;
    default:
	oper_name="..";
    }
#endif
    nestings=0;
    start_end_sorted_search(l,&lp);
    get_region(&lp,&l_reg);
    get_region(&rp,&r_reg);
    /* If left or right region list was empty, we can return empty list */
    if (l_reg.start==-1 || r_reg.start==-1) return a;
    
    do
    {
	if (l_reg.end<r_reg.start && l_reg.start!=-1 )
	{
	    /* left region is first. Add to nest_stack
	       and nest queue */
	    if (nest_depth==evaluator->tmp_stack_size)
	    {
		evaluator->tmp_stack_size+=evaluator->tmp_stack_size/2;
		evaluator->tmp_stack=(Region *)sgrep_realloc(
		    evaluator->tmp_stack,
		    evaluator->tmp_stack_size*sizeof(Region));
	    }
	    evaluator->tmp_stack[nest_depth++]=l_reg;
	    nestings=0;
#ifdef DEBUG
	    if (nest_depth==1)
		fprintf(stderr," New q");
	    else fprintf(stderr," +");
	    fprintf(stderr,"(%d:%d)",l_reg.start,l_reg.end);
#endif
	    get_region(&lp,&l_reg);
	}
	else if (nest_depth>0)
	{
#ifdef DEBUG
	    fprintf(stderr," %d",r_reg.end);
#endif
	    if (type==L_ORDERED || type==LR_ORDERED)
		s=evaluator->tmp_stack[--nest_depth].end+1;
	    else s=evaluator->tmp_stack[--nest_depth].start;
	    if (type==R_ORDERED || type==LR_ORDERED)
		e=r_reg.start-1;
	    else e=r_reg.end;
	    
	    if (e>=s)
	    {
		/* If we have taken region from nest stack
		 * twice in row, it probably means, that
		 * we have a nested result list */
		nestings++;
		if (nestings==2)
		{
#ifdef DEBUG
		    if (!a->nested)
			fprintf(stderr,"nesting order detecded\n");
#endif
		    a->nested=1;
		    list_set_sorted(a,NOT_SORTED);
		}
		add_region(a,s,e);
	    }			
	    get_region(&rp,&r_reg);
	} else 
	{
	    get_region(&rp,&r_reg);
	}
    } while ( r_reg.start!=-1 );
    return a;
}

/*
 * Handles in operation 
 */
RegionList *in(RegionList *l,RegionList *r, int not)
/* Changed by PK in Febr 95 to capture the semantics of _proper_
containment */
{	
	ListIterator lp,rp;
	RegionList *a,*r2;
	Region r_reg,l_reg,r_reg2;
	char *oper_name;
#ifdef PROGRESS_REPORTS
	int prog;int prog_start;
#endif
	SGREPDATA(l);

#ifdef DEBUG
	fprintf(stderr,"in called\n");
#endif
	if (not) 
	{
		stats.not_in++;
		oper_name="not in";
	} else 
	{
		stats.in++;
		oper_name="in";
	}
	a=new_region_list(sgrep);
	
#ifdef OPTIMIZE_SORTS
	a->nested=l->nested;
#endif
	
	start_region_search(l,&lp);
	get_region(&lp,&l_reg);
	
	
       /* 
 	* To simplify things we do an outer function on right gc_list 
 	*/
#ifdef OPTIMIZE_SORTS
	if (r->nested)
	{
#endif
		r2=outer(r);
		r=r2;
#ifdef OPTIMIZE_SORTS
	} else r2=NULL;
#endif
	start_region_search(r,&rp);

#ifdef PROGRESS_REPORTS
	prog_start=LIST_SIZE(l)+LIST_SIZE(r);
	prog=0;
#endif

	get_region(&rp,&r_reg);
	while (r_reg.start!=-1 && l_reg.start!=-1)
	{
#ifdef DEBUG
		fprintf(stderr,"in: left=(%d,%d) right=(%d,%d)\n",
			l_reg.start,l_reg.end,
			r_reg.start,r_reg.end);
#endif
		if (l_reg.start<r_reg.start)
		{
			/* Left region starts before right -> can't be
			   in right region or any right region that follows
			   current one */
			if (not) add_region(a,l_reg.start,l_reg.end);
			get_region(&lp,&l_reg);
		} else /* l_reg.start>=r_reg.start */
		{
			if (l_reg.end<=r_reg.end)
			{
				/* left region is in right region */
/* Start PK Febr 95 */
				if (l_reg.start>r_reg.start ||
				    l_reg.end<r_reg.end)
				{	/* inclusion is proper */
					if (!not) add_region(a,l_reg.start,l_reg.end);
					get_region(&lp,&l_reg);
				} else { /* l_reg == r_reg */ 
					if (not) add_region(a,l_reg.start,l_reg.end);
					get_region(&lp,&l_reg);
				}
/* End PK Febr 95 */
			} else 	if (l_reg.start==r_reg.start)
			{
				/* Regions start from same place. Because
				no right region after current one can start 
				from same place we can skip left region */
				if (not) add_region(a,l_reg.start,l_reg.end);
				get_region(&lp,&l_reg);
			} else
			{
				/* left and right region are overlapping */
#ifdef DEBUG
				fprintf(stderr,"in overlap\n");
#endif
				get_region(&rp,&r_reg2);
				if (r_reg2.start==-1)
				{
					/* All right regions have been scanned */
					if ( l_reg.start > r_reg.end )
					{
						/* Left region end after last right region. 
						   We can fall out of loop */
						r_reg=r_reg2;
					} else
					{
						/* Next left region might still be in right 
						   region */
						if (not) add_region(a,l_reg.start, l_reg.end);
						get_region(&lp,&l_reg);
					}
				} else
				{
					/* There are still right regions */
					if ( l_reg.start >= r_reg2.start )
					{
						/* Since left region starts after new right region,
						 * We can safely skip previous right */
						r_reg=r_reg2;
					} else
					{
						/* Left region is not in previous or next 
						   right region */
						prev_region(&rp,&r_reg2);
						if (not) add_region(a,l_reg.start, l_reg.end);
						get_region(&lp,&l_reg);
					}
				}
			}
		}
	}

#ifdef DEBUG
	fprintf(stderr,"in fall out\n");
#endif
/* If we have "not in" and right gc_list is empty, we need to copy
   rest of left list */
	if (not)
	{
		while (l_reg.start!=-1)
		{
			add_region(a,l_reg.start,l_reg.end);
			get_region(&lp,&l_reg);
		}
	}

/* because we created list r2 here, we free it here */
	if (r2!=NULL) free_gclist(r2);
	return a;
}

/* 
 * Handles outer function 
 */
RegionList *outer(RegionList *gcl)
{
	ListIterator p;
	Region reg1,reg2;
	RegionList *a;
#ifdef PROGRESS_REPORTS
	char *oper_name;
	int prog;int prog_start;
#endif
	SGREPDATA(gcl);
#ifdef PROGRESS_REPORTS
	oper_name="outer";
	prog_start=LIST_SIZE(gcl);
	prog=0;
#endif

	stats.outer++;
	reg2.start=0;
	a=new_region_list(sgrep);
	start_region_search(gcl,&p);
	get_region(&p,&reg1);

	/* if we had empty gc list */
	if (reg1.start==-1) return a;
		
	/* If there are many regions starting from same place, we choose the
	   longest */
	get_region(&p,&reg2);
	while (reg2.start==reg1.start && reg2.end>reg1.end)
	{
		reg1=reg2;
		get_region(&p,&reg2);
	}
	
	while(reg1.start!=-1 && reg2.start!=-1)
	{
		if (reg2.end>reg1.end && reg2.start!=reg1.start)
		{
			/* reg2 ends after reg1 -> no nesting */
			add_region(a,reg1.start,reg1.end);
			reg1=reg2;
		}
		get_region(&p,&reg2);
		/* If regions start from same place, nesting is guaranteed */
		if (reg2.start==reg1.start)
		{
			reg1=reg2;
			get_region(&p,&reg2);
		}
	}
	add_region(a,reg1.start,reg1.end);
	return a;
}

/*
 * Handles inner function 
 */
RegionList *inner(Evaluator *evaluator,RegionList *gcl)
{
    ListIterator p;
    int inq_ind=0;
    RegionList *a=NULL;
    Region n_reg,c_reg;
    int i;
    Region *inner_stack;
    SGREPDATA(evaluator);
#ifdef PROGRESS_REPORTS
    char *oper_name;
    int prog;int prog_start;
#endif

#ifdef DEBUG
    fprintf(stderr,"inner called\n");
#endif	
    stats.inner++;
    a=new_region_list(sgrep);
    inner_stack=evaluator->tmp_stack;

#ifdef PROGRESS_REPORTS
    prog_start=LIST_SIZE(gcl);
    prog=0;
    oper_name="inner";
#endif

    start_region_search(gcl,&p);
    get_region(&p,&c_reg);
    while (c_reg.start!=-1) {
	get_region(&p,&n_reg);
	assert(n_reg.start>=c_reg.start || n_reg.start==-1 );
	if ( n_reg.start>c_reg.end || n_reg.start==-1 )
	{
	    /* n_reg and c_reg are separate. Therefore c_reg must
	       be innermost */
	    /* Now we can empty inner_stack */
#ifdef DEBUG
	    fprintf(stderr,"empty inner stack (%d regions)\n",inq_ind);
#endif
	    for (i=0;i<inq_ind;i++)
	    {
		assert(inner_stack[i].start<=c_reg.start);

		if (inner_stack[i].end<c_reg.end)
				/* Region in inner_stack was innermost */
		    add_region(a,inner_stack[i].start,
			       inner_stack[i].end);
	    }
	    inq_ind=0;
	    add_region(a,c_reg.start,c_reg.end);
	} else if ( n_reg.end>c_reg.end )
	{
	    /* n_reg and c_reg are overlapping. Let's add c_reg
	       to inner_stack */
	    if (evaluator->tmp_stack_size==inq_ind)
	    {
		evaluator->tmp_stack_size+=evaluator->tmp_stack_size/2;
		inner_stack=(Region *)
		    sgrep_realloc(inner_stack,
				  evaluator->tmp_stack_size*
				  sizeof(Region));
		evaluator->tmp_stack=inner_stack;
	    }
	    inner_stack[inq_ind++]=c_reg;
	} else {
	    /* if neither of the previous if's was taken, 
	       c_reg contains n_reg. We remove regions containing n_reg from
	       inner_stack */
	    while(inq_ind &&  
		  n_reg.start>=inner_stack[inq_ind-1].start &&
		  n_reg.end<=inner_stack[inq_ind-1].end )
	    {
		inq_ind--;
	    }
	}
	c_reg=n_reg;
	if (inq_ind) 
	    assert(c_reg.start<inner_stack[inq_ind-1].start ||
		   c_reg.end>inner_stack[inq_ind-1].end);
    }
    return a;
}

RegionList *containing(Evaluator *evaluator,RegionList *l,
			   RegionList *r,int not)
/* Changed by PK in Febr 95 to capture the semantics of _proper_
containment */
{
	ListIterator lp,rp;
	RegionList *a,*r2;
	Region r_reg,l_reg;
	SGREPDATA(evaluator);
#ifdef PROGRESS_REPORTS
	char *oper_name;
	int prog;int prog_start;
#endif

#ifdef DEBUG
	fprintf(stderr,"containing called\n");
#endif
	if (not) stats.not_containing++; else stats.containing++;
	a=new_region_list(sgrep);
#ifdef OPTIMIZE_SORTS
	a->nested=l->nested;
#endif
	start_region_search(l,&lp);
	get_region(&lp,&l_reg);

/* To simplify things we do an inner function on right gc_list */
#ifdef OPTIMIZE_SORTS
	if (r->nested)
	{
#endif
		r2=inner(evaluator,r);
		r=r2;
#ifdef OPTIMIZE_SORTS
	} else r2=NULL;
#endif

#ifdef PROGRESS_REPORTS
	oper_name= (not) ? "not containing" : "containing";
	prog=0;
	prog_start=LIST_SIZE(l)+LIST_SIZE(r);
#endif
	start_region_search(r,&rp);
	
	get_region(&rp,&r_reg);
	while (r_reg.start!=-1 && l_reg.start!=-1)
	{
		if ( l_reg.start>r_reg.start )
		{
			/* right starts before left */
			get_region(&rp,&r_reg);
		} else if ( l_reg.end>=r_reg.end )
		{
			/* left contains right */
/* Start PK Febr 95 */
			if (l_reg.start<r_reg.start ||
			    l_reg.end>r_reg.end)
			{	/* Containment is proper */
				if (!not) add_region(a,l_reg.start,l_reg.end);
				get_region(&lp,&l_reg);
			} else { /* l_reg == r_reg */
				if (not) add_region(a,l_reg.start,l_reg.end);
				get_region(&lp,&l_reg);
			}
/* End PK Febr 95 */
		} else {
			/* left comes after right */
			if (not) add_region(a,l_reg.start,l_reg.end);
			get_region(&lp,&l_reg);
		}	
	}
	/* When right list ended, there still might be something in left list */
	while (not && l_reg.start!=-1)
	{
		add_region(a,l_reg.start,l_reg.end);
		get_region(&lp,&l_reg);
	}
/* because we created list r2 here, we free it here */
	if (r2!=NULL) free_gclist(r2);
	return a;
}

RegionList *equal(RegionList *l,RegionList *r,int not)
/* Intersection of GC_LISTs *l and *r */
/* PK Febr '95 */
{
	ListIterator lp,rp;
	RegionList *a;
	Region r_reg,l_reg;
	SGREPDATA(l);
#ifdef PROGRESS_REPORTS
	char *oper_name;
	int prog;int prog_start;
#endif

#ifdef DEBUG
	fprintf(stderr,"equal called\n");
#endif
	if (not) stats.not_equal++; else stats.equal++;
	a=new_region_list(sgrep);
#ifdef OPTIMIZE_SORTS
	a->nested=l->nested;
#endif
	start_region_search(l,&lp);
	get_region(&lp,&l_reg);


#ifdef PROGRESS_REPORTS
	oper_name= (not) ? "not equal" : "equal";
	prog=0;
	prog_start=LIST_SIZE(l)+LIST_SIZE(r);
#endif
	start_region_search(r,&rp);
	get_region(&rp,&r_reg);


	while (r_reg.start!=-1 && l_reg.start!=-1)
	{
		if ( l_reg.start<r_reg.start )
		{
			if (not) add_region(a,l_reg.start,l_reg.end);
			get_region(&lp,&l_reg);
		} else if ( r_reg.start<l_reg.start )
		{
			get_region(&rp,&r_reg);
		} else  /*  r_reg.start=l_reg.start */
			if ( l_reg.end<r_reg.end )
			{
				if (not) add_region(a,l_reg.start,l_reg.end);
				get_region(&lp,&l_reg);
			} else if ( r_reg.end<l_reg.end )
			{
				get_region(&rp,&r_reg);
			} else /* l_reg = r_reg */
			{
				if (!not) add_region(a,l_reg.start,l_reg.end);
				get_region(&rp,&r_reg);
				get_region(&lp,&l_reg);
			}
	}
	/* When right list ended, there still might be something in left list */
	while (not && l_reg.start!=-1)
	{
		add_region(a,l_reg.start,l_reg.end);
		get_region(&lp,&l_reg);
	}
	return a;

} /* END equal(RegionList *l,RegionList *r,int not) */

/*
 * Here we implement concat operation, which concats all overlapping regions
 * into one region and removes all nestings
 */
RegionList *concat(RegionList *l)
{
    SGREPDATA(l);
	ListIterator lp;
	RegionList *a;
	Region reg1,reg2;
#ifdef PROGRESS_REPORTS
	char *oper_name;
	int prog;int prog_start;
#endif

#ifdef DEBUG
	fprintf(stderr,"concat called\n");
#endif
	stats.concat++;
	a=new_region_list(sgrep);
	start_region_search(l,&lp);
	get_region(&lp,&reg1);
	
	/* We had empty list */
	if (reg1.start==-1) return a;

#ifdef PROGRESS_REPORTS
	oper_name="concat";
	prog=0;
	prog_start=LIST_SIZE(l);
#endif
	get_region(&lp,&reg2);
	
	while (reg2.start!=-1)
	{
		if (reg2.start>reg1.end+1)
		{
			/* separate regions, no concat */
			add_region(a,reg1.start,reg1.end);
			reg1=reg2;
		} else if ( reg2.end>reg1.end )
		{
			/* We found overlapping */
			reg1.end=reg2.end;
		}
		get_region(&lp,&reg2);
	}
	add_region(a,reg1.start,reg1.end);
	return a;
}

/*
 * Here we implement extracting operation
 */
RegionList *extracting(RegionList *l,RegionList *r)
{
    SGREPDATA(l);
	ListIterator lp,rp,tmpp;
	RegionList *a,*r2,*tmp,*new_tmp;
	Region l_reg,r_reg;
	int prev_s=-1;
	int prev_e=-1;
	int last_tmp;
#ifdef PROGRESS_REPORTS
	char *oper_name;
	int prog;int prog_start;
#endif

#ifdef DEBUG
	fprintf(stderr,"extracting called\n");
#endif
	stats.extracting++;
	/* to simplify things we do concat on right gc_list. Result stays
	   the same anyway */
	r2=concat(r);
	r=r2;
	
	a=new_region_list(sgrep);
#ifdef OPTIMIZE_SORTS
	a->nested=l->nested;
#endif
	tmp=new_region_list(sgrep);
	start_region_search(tmp,&tmpp);

#ifdef PROGRESS_REPORTS
	oper_name="extracting";
	prog=0;
	prog_start=LIST_SIZE(l);
#endif
	
	start_region_search(l,&lp);
	get_region(&lp,&l_reg);
	start_region_search(r,&rp);
	get_region(&rp,&r_reg);

	while ( l_reg.start!=-1 )
	{
		if ( l_reg.end<r_reg.start || r_reg.start==-1 )
		{
			/* Regions are separate, left starting first.
 			   no cutting */
 			if ( prev_s!=l_reg.start || prev_e!=l_reg.end )
 			{				
#ifdef DEBUG		
	fprintf(stderr,"extracting adding 1(%d,%d)\n",l_reg.start,l_reg.end);
#endif
				prev_s=l_reg.start;
				prev_e=l_reg.end;
				add_region(a,l_reg.start,l_reg.end);
			}
			l_reg=first_of(&lp,&tmpp);
		} else if ( r_reg.end<l_reg.start )
		{
			/* Regions are separate right starting first.
			   we skip right */
#ifdef DEBUG
			fprintf(stderr,"skipping right, left=(%d,%d) right=(%d,%d)\n",
				l_reg.start,l_reg.end,r_reg.start,r_reg.end);
#endif
			get_region(&rp,&r_reg);
		} else
		{
			/* We need to do clipping. */
			new_tmp=new_region_list(sgrep);
/* OBSOLETE			new_tmp->start_sorted_list=NULL;
   must_be_sorted=FALSE; */
			last_tmp=-1;
#ifdef DEBUG
			fprintf(stderr,"cutting loop, cutter (%d,%d)\n",r_reg.start,r_reg.end);
#endif
			while ( l_reg.start!=-1 && l_reg.start<=r_reg.end )
			{
			    if (l_reg.start<r_reg.start && 
				( prev_s!=l_reg.start ||
				  prev_e!=r_reg.start-1 ))
			    {
				prev_s=l_reg.start;
				prev_e=r_reg.start-1;
				
#ifdef DEBUG
				fprintf(stderr,"extracting adding 2(%d,%d)\n",l_reg.start,r_reg.start-1);
#endif		
				add_region(a,l_reg.start,r_reg.start-1);
			    }
			    if (r_reg.end<l_reg.end)
			    {
#ifdef DEBUG
				fprintf(stderr,"(%d,%d)<-new_tmp\n",r_reg.end+1,l_reg.end);
#endif
				if (l_reg.end<last_tmp) {
				    list_set_sorted(new_tmp,NOT_SORTED);
				}
				add_region(new_tmp,r_reg.end+1,l_reg.end);
				last_tmp=l_reg.end;
			    }
			    l_reg=first_of(&lp,&tmpp);
			}
			if (l_reg.start!=-1) prev_region(&lp,&l_reg);
				
			assert (tmpp.ind==tmp->length &&
				tmpp.node->next==NULL);

			free_gclist(tmp);
#ifdef PROGRESS_REPORTS
			prog--;
			prog_start+=LIST_SIZE(new_tmp);
#endif
			tmp=new_tmp;
			start_region_search(tmp,&tmpp);
			/* Left region is now handled -> skip to next */
			l_reg=first_of(&lp,&tmpp);
		}
	}
	free_gclist(r2);
	free_gclist(tmp);
	return a;
}

/*
 * Join operation
 */
RegionList *join(Evaluator *evaluator,RegionList *l,int number)
{
	RegionList *a;
	ListIterator p1,p2;
	Region r1,r2,prev_r1,prev_r2;
	int i;
	SGREPDATA(l);
#ifdef PROGRESS_REPORTS
	char *oper_name;
	int prog;int prog_start;
#endif
	
#ifdef DEBUG
	fprintf(stderr,"join called %d\n",number);
#endif
	assert(number>0);

	stats.join++;
	a=new_region_list(sgrep);
#ifdef OPTIMIZE_SORTS
	a->nested=l->nested;
#endif	
	if ( l->first==NULL )
	{
		/* This is an optimized chars node */
		to_chars(a,(l->chars+1)*number,
			 flist_total(evaluator->files)-1);
		return a;
	}
	
	/* List is smaller than join number, so return list is empty */
	if (LIST_SIZE(l)<number) return a;

#ifdef PROGRESS_REPORTS
	oper_name="join";
	prog=0;
	prog_start=LIST_SIZE(l);
#endif

	start_region_search(l,&p1);
	start_region_search(l,&p2);

	prev_r2.start=-1;	
	prev_r1.end=-1;	
	for (i=number;i>0;i--)
	{
		get_region(&p1,&r1);
		assert(r1.start!=-1);
	}
	while (r1.start!=-1)
	{
		get_region(&p2,&r2);
		if (r2.start==prev_r2.start)
		{
/*PK			if (prev.end<r2.end) */

			if (r1.end<=prev_r1.end)
			{
				list_set_sorted(a,NOT_SORTED);
			}
		}
		add_region(a,r2.start,r1.end);
		prev_r1=r1; 
		get_region(&p1,&r1);
		prev_r2=r2; 
	}
	if (list_get_sorted(a)!=START_SORTED)
	{ 
	  	remove_duplicates(a); /* There might be duplicates in a */
	};
	return a;	
}

RegionList *first(RegionList *input, int num) {
    /* It would be cool, if i just could truncate the input list.
     * Too bad that checking for if i just could is too complicated */
    RegionList *result;
    ListIterator i;
    Region r;
    SGREPDATA(input);

    result=new_region_list(sgrep);
    start_region_search(input,&i);
    get_region(&i,&r);
    while(num>0 && r.start!=-1) {
	add_region(result,r.start,r.end);
	get_region(&i,&r);
	num--;
    }
    return result;
}

RegionList *last(RegionList *input, int num) {
    RegionList *result;
    ListIterator i;
    Region r;
    SGREPDATA(input);

    num=LIST_SIZE(input)-num;
    if (num<0) num=0;
    result=new_region_list(sgrep);
    start_region_search_from(input,num,&i);
    get_region(&i,&r);
    while(r.start!=-1) {
	add_region(result,r.start,r.end);
	get_region(&i,&r);	
    }
    return result;    
}

RegionList *first_bytes(RegionList *input, int num) {
    ListIterator i;
    Region r1,r2;
    RegionList *result;


    assert(num>=0);
    result=new_region_list(input->sgrep);
    if (num==0) return result;

    result->nested=input->nested;
    start_region_search(input,&i);
    r2.start=-1;
    get_region(&i,&r1);

    /* I too used to think that first_bytes() is a really simple operation..
     * Too bad it didn't last. */
    while(r1.start!=-1) {
	if (r1.end-r1.start+1>=num && 
	    (r1.start!=r2.start || r1.start+num-1!=r2.end)) {
	    r1.end=r1.start+num-1;
	    add_region(result,r1.start,r1.end);
	}
	get_region(&i,&r2);
	if (r2.start==-1) {
	    r1.start=-1;
	} else if (r2.end-r2.start+1>=num && 
		   (r1.start!=r2.start || r2.start+num-1!=r1.end)) {
	    r2.end=r2.start+num-1;
	    add_region(result,r2.start,r2.end);
	    get_region(&i,&r1);
	} else {
	    get_region(&i,&r1);
	}
    }
    return result;
}


RegionList *last_bytes(RegionList *input, int num) {
    ListIterator i;
    Region r1,r2;
    RegionList *result;

    /* This could probably be done faster, without not requiring to
     * set result as NOT_SORTED and remove_duplicates() */
    assert(num>=0);
    result=new_region_list(input->sgrep);    
    if (num==0) return result;

    if (input->nested) {
	list_set_sorted(result,NOT_SORTED); /* Sad but true */
	result->nested=1;
    }
    start_region_search(input,&i);
    r2.start=-1;
    get_region(&i,&r1);
    while(r1.start!=-1) {
	if (r1.end-r1.start+1>=num && 
	    (r1.end!=r2.end || r1.end+1-num!=r2.start)) {
	    r1.start=r1.end+1-num;
	    add_region(result,r1.start,r1.end);
	}
	get_region(&i,&r2);
	if (r2.start==-1) {
	    r1.start=-1;
	} else if (r2.end-r2.start+1>=num && 
		   (r2.end!=r1.end || r2.end+1-num!=r1.start)) {
	    r2.start=r2.end+1-num;
	    add_region(result,r2.start,r2.end);
	    get_region(&i,&r1);
	} else {
	    get_region(&i,&r1);
	}
    }
    if (result->nested) {
	remove_duplicates(result);
    }
	
    return result;
}

/* 
 * Handles ordering which does _not_ produce nesting gc-lists. 
 * For example '"--" quote "--"' to catch SGML comments.
 */
RegionList *quote(RegionList *l,RegionList *r,int type)
{
	ListIterator lp,rp;
	RegionList *a;
	Region r_reg,l_reg;              
	SGREPDATA(l);
#ifdef PROGRESS_REPORTS
	char *oper_name;
	int prog;int prog_start;
#endif

#ifdef DEBUG
	fprintf(stderr,"quote called\n");
#endif	
	stats.quote++;
	a=new_region_list(sgrep);

#ifdef PROGRESS_REPORTS
	prog_start=LIST_SIZE(r);
	prog=0;
	switch (type) {
	case L_QUOTE:
		oper_name="_quote";
		break;
	case R_QUOTE:
		oper_name="quote_";
		break;
	case LR_QUOTE:
		oper_name="_quote_";
		break;
	default:
		oper_name="quote";
	}
#endif
	start_region_search(r,&rp);
	start_region_search(l,&lp);
	get_region(&lp,&l_reg);
	get_region(&rp,&r_reg);

	/* If left or right region list was empty, we can return empty list */
	if (l_reg.start==-1 || r_reg.start==-1) return a;
	do {
		/* Skip until we find ending quote after start quote */
		while (l_reg.end>=r_reg.start && r_reg.start!=-1) {
			get_region(&rp,&r_reg);
		}
		if (r_reg.start>=0) {
			/* Add region using operation type */
			switch (type) {
			case QUOTE:
				add_region(a,l_reg.start, r_reg.end);
				break;
			case L_QUOTE:
				add_region(a,l_reg.end+1, r_reg.end);
				break;
			case R_QUOTE:
				add_region(a,l_reg.start, r_reg.start-1);
				break;
			case LR_QUOTE:
				/* No empty regions */
				if (l_reg.end+1<r_reg.start) {
					add_region(a,l_reg.end+1,r_reg.start-1);
				} 
				break;
			default:
			    abort();
			/* Skip until starting quote is after last ending
			   quote */
			}
			while (l_reg.start<=r_reg.end && l_reg.start!=-1) {
				get_region(&lp,&l_reg);
			}
		}
	} while ( l_reg.start!=-1 && r_reg.start!=-1);
	return a;
}

/*
 * NOTE: assumes that require_start_sorted_array has been called for
 * list
 */
int list_find_first_start(RegionList *list, int start, int index) {
    int end;
    int middle;
    Region region;

    assert(list->start_sorted_array);
    end=LIST_SIZE(list);
    assert(start<=end);

    middle=1;
    while(start+middle<end) {
	region_at(list,start+middle,&region);
	/* printf("lffs1(%d): %d %d %d (%d,%d)\n",index,start,middle,end,
	   region.start,region.end); */
	if (region.start<index) {
	    start+=middle+1;
	    middle+=middle;
	} else {
	    end=start+middle;
	    break;
	}
    }

    while(start!=end) {
	middle=(end+start)/2;
	region_at(list,middle,&region);
	/* printf("lffs2(%d): %d %d %d (%d,%d)\n",index,start,middle,end,
	   region.start,region.end);  */
	if (region.start<index) {
	    start=middle+1;
	} else {
	    end=middle;
	}
    }
    return start;
}

RegionList *parenting(Evaluator *evaluator,RegionList *l, RegionList *r) {
    RegionList *result;
    Region parent,child;
    ListIterator child_i;
    int parent_i,parent_size;
    Region *stack=evaluator->tmp_stack;
    int sp=0; /* Stack pointer */
    SGREPDATA(l);

    stats.parenting++;

    /* Initialization */
    result=new_region_list(sgrep);
    if (LIST_SIZE(r)>1) result->nested=1;

    list_require_start_sorted_array(l);
    parent_size=LIST_SIZE(l);
    if (parent_size==0) return result;
    parent_i=0;
    region_at(l,parent_i,&parent);
 
    start_region_search(r,&child_i);
    get_region(&child_i,&child);

    list_set_sorted(result,NOT_SORTED);
    /* The parenting loop */
    while(child.start!=-1 && (sp>0 || parent_i<parent_size)) {

	/* This should be the most frequent case: parent candidate 
	 * ends before child has even started. Just simply skip to next
	 * parent */
	while(parent.end<child.start && parent_i<parent_size) {
	    parent_i=list_find_first_start(l,parent_i,parent.end+1);
	    if (parent_i<parent_size) {
		region_at(l,parent_i,&parent);	    
	    }
	}
	
	/* Skip child candidates as long as
	 * 0. stack is empty
	 * 1. there is childs
	 * 2. child is not contained in parent
	 * 3. parent ends after child starts
	 */
	if (sp==0) {
	    while(child.start!=-1 && 
		  (!contains(parent,child)) &&
		  parent.end>child.start) {
		get_region(&child_i,&child);
	    }
	}

	/* No more childs --> nothing to do anymore */
	if (child.start==-1) break;
	
	if (parent_i<parent_size && contains(parent,child)) {
	    /* Now we know, that the child is contained in parent */

	    /* Now add the known good candidate to stack */
	    if (evaluator->tmp_stack_size==sp) {
		/* Allocate more space (previous_size*1.5) */
		evaluator->tmp_stack_size+=evaluator->tmp_stack_size/2;
		stack=(Region *)sgrep_realloc(stack,
						     evaluator->tmp_stack_size*
						     sizeof(Region));
		evaluator->tmp_stack=stack;
	    }
	    stack[sp++]=parent;
	    parent_i++;
	    if (parent_i<parent_size) {
		region_at(l,parent_i,&parent);
	    }
	} else {
	    /* Now the innermost containing element is the topmost element
	     * in the stack. If stack is empty there is no containing element
	     */
	    if (sp>0) {
		assert(contains(stack[sp-1],child));
		add_region(result,stack[sp-1].start,stack[sp-1].end);
		/* This child is now handled. Next child */
		get_region(&child_i,&child);

		/* Now remove the regions which do not contain the new child
		 * from stack */ 
		if (child.start!=-1) {
		    while(sp>0 && stack[sp-1].end<child.end) {
			assert(stack[sp-1].start<=child.start);
			sp--;		    
		    }
		}
	    }	    
	}
    }
    /* The result list is not sorted and might contain duplicates */
    remove_duplicates(result);
    return result;
}


RegionList *childrening(RegionList *children, 
			RegionList *parents) {
    RegionList *result;
    ListIterator parent_i;
    int child_number;
    Region parent,child,next_child;
    int childrens;
    RegionList *saved_parents;
    int last_parent_end;
    int loops=0;
    int first;
    SGREPDATA(children);
    
    stats.childrening++;

    /* Initialization */
    start_region_search(parents,&parent_i);    
    list_require_start_sorted_array(children);
    get_region(&parent_i,&parent);
    saved_parents=new_region_list(sgrep);
    saved_parents->nested=1;
    child_number=0;
    childrens=LIST_SIZE(children);
    result=new_region_list(sgrep);
    first=parent.start;

    /* While there is parents and child candidates left */
    while(first!=-1) { 

	/* Find first possible child candidate */
	child_number=list_find_first_start(children,child_number,first);
	
	if (child_number<childrens) {
	    region_at(children,child_number,&child);

	    /*
	     * Now the ugly part. 
	     * Deal with parent region being also a child candidate
	     */	    
	    if (child.start==parent.start && child.end==parent.end) {
		first++;
		continue;
	    }

	    /* Deal with multiple child candidate regions having same start 
	     * point. 
	     */	    
	    while (contains(parent,child) &&
		   child_number+1<childrens) {
		/* UGH! */
		region_at(children,child_number+1,&next_child);
		if (next_child.start==child.start && 
		    contains(parent,next_child)) {
		    /* We found a better child candidate */
		    assert(next_child.end>child.end);
		    child_number++;
		    child=next_child;
		} else {
		    break;
		}		    
	    }
	    
	    assert(child_number<childrens && parent.start<=child.start);

	    /* Now check the final candidate */
	    if (contains(parent,child)) {
		/* Add found child candidate to result list*/
		add_region(result,child.start,child.end);
		first=child.end+1;
	    } else {
		/* This parent is handled; find next */
		last_parent_end=parent.end;
		get_region(&parent_i,&parent);
		while(parent.start!=-1 && parent.start<=last_parent_end) {
		    /* Overlapping or nested parents. 
		     * Handle it in next iteration */
		    add_region(saved_parents,parent.start,parent.end);
		    get_region(&parent_i,&parent);
		}
		first=parent.start;
	    }
	} else {
	    first=-1;
	}
	
	/* Check, if we need to restart search with saved parents */
	if (first==-1 && LIST_SIZE(saved_parents)>0) {
	    /* We need to restart */
	    if (loops>0) {
		/* Free region lists created here */
		delete_region_list(parents);
	    }
	    loops++;
	    /* fprintf(stderr,"Childrening: loop #%d\n",loops); */
	    parents=saved_parents;
	    start_region_search(parents,&parent_i);
	    get_region(&parent_i,&parent);
	    saved_parents=new_region_list(sgrep);	    
	    saved_parents->nested=1;
	    child_number=0;
	    /* After second loop it is possible that result contains
	     * unordered nested regions */
	    list_set_sorted(result,NOT_SORTED);
	    result->nested=1;
	    first=parent.start;
	}
    }

    /* Clean up */
    delete_region_list(saved_parents);
    if (loops>0) delete_region_list(parents);

    if (loops>0) {
	/* Result list might be nested or contain duplicates only if
	 * we needed multiple passes */
	remove_duplicates(result);
    }

    return result;
}

RegionList *eval_near(RegionList *l, 
		 RegionList *r, int how_near) {
    RegionList *first_list, *second_list;
    ListIterator first_i, second_i;
    Region result,first,second;
    RegionList *result_list;
    SGREPDATA(l);

    /* To simplify things, we outer() on first and second */
    first_list= (l->nested) ? outer(l) : l;
    second_list= (r->nested) ? outer(r) : r;
    
    /* Initialize */
    start_region_search(first_list,&first_i);
    get_region(&first_i,&first);
    start_region_search(second_list,&second_i);
    get_region(&second_i,&second);
    result_list=new_region_list(sgrep); 
    result.start=result.end=-1;

    /* Do the job */
    while(first.start!=-1 && second.start!=-1) {

	if (first.start<second.start ||
	    (first.start==second.start && first.end<second.end)) {	    
	    /* first starts first */
	    
	    if (second.start-1-first.end <= how_near) {		
		/* Found a match */

		/* Check for nesting result */
		assert(first.start>=result.start);
		if (second.end>result.end) {
		    /* No nesting. So we have a proper match
		     * Now we can add the region from previous iteration */
		    if (result.start>0) {
			add_region(result_list,result.start,result.end);    
		    }
		    /* Save the match to be added later */
		    result.start=first.start;
		    result.end=second.end;
		}
	    }
	    get_region(&first_i,&first);

	} else {

	    /* second starts first */
	    
	    if (first.start-1-second.end <= how_near) {		
		/* Found a match */

		/* Check for nesting result */
		assert(second.start>=result.start);
		if (first.end>result.end) {
		    /* No nesting. So we have a proper match
		     * Now we can add the region from previous iteration */
		    if (result.start>=0) {
			add_region(result_list,result.start,result.end);    
		    }
		    /* Save the match to be added later */
		    result.start=second.start;
		    result.end=first.end;
		}
	    }
	    get_region(&second_i,&second);
	}
    }
    
    /* Free the outer() lists, if they we're created */
    if (first_list!=l) {
	delete_region_list(first_list);
    }
    if (second_list!=r) {
	delete_region_list(second_list);
    }

    /* Add the last result */
    if (result.start>0) {
	add_region(result_list,result.start,result.end);
    }

    return result_list;
}

RegionList *near_before(RegionList *l, 
		 RegionList *r, int how_near) {
    RegionList *first_list, *second_list;
    ListIterator first_i;
    int second_size;
    int second_i;
    Region first;
    RegionList *result_list;
    SGREPDATA(l);

    /* To simplify things, we outer() on first and second */
    first_list= (l->nested) ? outer(l) : l;
    second_list= (r->nested) ? outer(r) : r;
    
    /* Initialize */
    start_region_search(first_list,&first_i);
    get_region(&first_i,&first);
    if (first.start==-1) {
	return new_region_list(sgrep);
    }
    list_require_start_sorted_array(second_list);
    second_size=LIST_SIZE(second_list);
    second_i=list_find_first_start(second_list,0,first.end+1);
    result_list=new_region_list(sgrep); 

    /* Do the job */
    while(first.start!=-1 && second_i<second_size) {
	    
	    if (region_lvalue_at(second_list,second_i).start-1-
		first.end <= how_near) {		
		/* Found a match */
		add_region(result_list,
			   first.start,
			   region_lvalue_at(second_list,second_i).end);
	    }
	    /* Next */
	    get_region(&first_i,&first);
	    if (first.start!=-1) {
		second_i=list_find_first_start(second_list,
					       second_i,first.end+1);
	    }
    }
    
    /* Free the outer() lists, if they we're created */
    if (first_list!=l) {
	delete_region_list(first_list);
    }
    if (second_list!=r) {
	delete_region_list(second_list);
    }

    return result_list;
}
