/*
	System: Structured text retrieval tool sgrep.
	Module: optimize.c 
	Author: Pekka Kilpeläinen & Jani Jaakkola
	Description: Optimizes the operator tree by removing identical
		     subtrees. ( optimize_tree() )
	Version history: Original version February 1995 by JJ & PK
	Copyright: University of Helsinki, Dept. of Computer Science
*/

#include <string.h>

#include "sgrep.h"

/*
 * If you wan't to see how operator tree is shrinked, define this
 */
/* #define DEBUG_OPTTREE */

typedef struct {
    SgrepData *sgrep;
    int label_c;
    ParseTreeNode **root;
    ParseTreeLeaf **phrase_list;
    int tree_size;
    int optimized_nodes;
    int optimized_phrases;
} Optimizer;


/*
 * sorts phrase list, so that same phrases can easily be detected
 */
struct PHRASE_NODE *qsort_phrases(struct PHRASE_NODE **phrase_list)
{
	struct PHRASE_NODE *list1,*list2,*comp,*next,*p_list;
	p_list=*phrase_list;
#ifdef DEBUG
	fprintf(stderr,"\nqsort called ");
#endif
	if (p_list==NULL) 
	{
		return NULL; /* Empty list. Return from recursion */
	}
	comp=p_list;
#ifdef DEBUG
	fprintf(stderr,"comp=%s\n",comp->phrase->s);
#endif
	p_list=p_list->next;
	if (p_list==NULL)
	{
		/* Only one phrase in list. Return from recursion */
		return *phrase_list;
	}
	
	list1=NULL;
	list2=comp;
	comp->next=NULL;
	while(p_list!=NULL)
	{
		next=p_list->next;
		if ( strcmp((char *)comp->phrase->s,
		     (char *)p_list->phrase->s)<0 )
		{
#ifdef DEBUG			
				fprintf(stderr,"list2+%s\n",p_list->phrase->s);
#endif
			p_list->next=list2;
			list2=p_list;
		} else
		{
#ifdef DEBUG
			fprintf(stderr,"list1+%s\n",p_list->phrase->s);
#endif
			p_list->next=list1;
			list1=p_list;
		}
		p_list=next;
	}
	/* order should be now list1 .. comp .. list2 */
	comp=qsort_phrases(&list2);
#ifdef DEBUG
	printf("vika on %s\n",comp->phrase->s);
#endif
	if (list1==NULL) 
	{
		*phrase_list=list2;
		return comp;
	}
	qsort_phrases(&list1)->next=list2;
	*phrase_list=list1;
	return comp;
}

/*
 * Merges duplicate phrases in phrase list
 */
void remove_duplicate_phrases(Optimizer *o)
{
	struct PHRASE_NODE *pn;
	struct PHRASE_NODE *lpn=NULL;
	struct PHRASE_NODE *tmp;
	SgrepData *sgrep=o->sgrep;
	char *last;
	
	/* we need to sort phrase list first */
	qsort_phrases(o->phrase_list);
	pn=*o->phrase_list;
	
	last=""; /* It's not possible to have empty phrase in the list,
		    so this can never be matched */
	
	while (pn!=NULL)
	{
		if (strcmp(last,(char *)pn->phrase->s)==0)
		{
#ifdef DEBUG
			fprintf(stderr," skipping duplicate\n");
#endif
			/* Phrase was already in the list */
			
			/* We give parent same label the first alike phrase had */
			pn->parent->label_left=o->label_c;
			/* Removing pn from phrase list */
			lpn->next=pn->next;
			pn->parent->leaf=lpn;
			/* Freeing memory allocated to pn */
			tmp=pn;
			pn=pn->next;
			assert(pn==NULL || (
			    pn->parent!=NULL && 
			    pn->parent->label_left==LABEL_PHRASE
			    ));
			delete_string(tmp->phrase);
			tmp->phrase=NULL;
			sgrep_free(tmp);
			
			/* Statistics... */
			o->optimized_phrases++;
		} 
		else
		{
			last=(char *)pn->phrase->s;
			o->label_c++;
			pn->parent->label_left=o->label_c;
			lpn=pn;
			pn=pn->next;

			assert(pn==NULL || pn->parent!=NULL);
			assert(pn==NULL || pn->parent->label_left==LABEL_PHRASE);

#ifdef DEBUG
			fprintf(stderr,"Checking duplicates for \"%s\" having label %d\n"
				,last,label_c);
#endif
		}
	}		
}

/* 
 * Recursively adds pointers to parents to every tree and phrase node 
 * counts also operator tree size
 */
int add_parents(ParseTreeNode *node,ParseTreeNode *parent)
{
    int nodes=1; /* This node */
    node->parent=parent;

    assert(node->label_right==LABEL_NOTKNOWN);
	
    node->refcount=0;
    if (node->oper==PHRASE)
    {
	node->leaf->parent=node;
    } else
    {
	assert(node->left!=NULL);
	nodes+=add_parents(node->left,node);
	if (node->right!=NULL)
	{
	    nodes+=add_parents(node->right,node);
	}
    }
    return nodes;
}

/*
 * Recursively creates a list of leaf nodes from parse tree
 */
int create_leaf_list(ParseTreeNode *root, ParseTreeNode **list, int ind)
{
	if (root->oper==PHRASE)
	{
		list[ind]=root;
		return ind+1;
	}
	ind=create_leaf_list(root->left,list,ind);
	if (root->right!=NULL)
	{
		ind=create_leaf_list(root->right,list,ind);
	}
	return ind;
}
	
#ifdef DEBUG
void dump_phrase_list(struct PHRASE_NODE *pn)
{
	while (pn!=NULL)
	{
		fprintf(stderr,"string %s parent label %d having %d references\n",
			pn->phrase->s,pn->parent->label,pn->parent->refcount);
		pn=pn->next;
	}
}
#endif

/*
 * Compares two tree nodes. returns 0 if they are alike
 * alike means: same oper, and same subtrees
 */
int comp_tree_nodes(ParseTreeNode **n1, ParseTreeNode **n2)
{
    int x;
    if ( ((*n1)->oper==JOIN || (*n1)->oper==FIRST || (*n1)->oper==LAST) &&
	 (*n2)->oper==(*n1)->oper ) {
	/* Join operation takes int parameter, which much be checked */
	x=(*n1)->number - (*n2)->number;
    } else {
	x=(*n1)->oper - (*n2)->oper;
    }
    if (x!=0) return x;

    /* if label_left==LABEL_CONS right subtree must be NULL ! */
    assert( (*n1)->label_left!=LABEL_CONS || (*n1)->right==NULL );
    assert( (*n2)->label_left!=LABEL_CONS || (*n2)->right==NULL );

    if ( (*n1)->label_left==LABEL_CONS && (*n2)->label_left==LABEL_CONS ) 
	return (*n1)!=(*n2); /* FIXME: this might be wrong */
    x=(*n1)->label_left - (*n2)->label_left;
    if (x!=0) return x;
    x=(*n1)->label_right - (*n2)->label_right;
    return x;
}

/*
 * sorts a leaf list using stdlib qsort and comp_tree_nodes 
 */
void sort_leaf_list(ParseTreeNode **leaf_list,int nmemb)
{
#ifdef DEBUG
	fprintf(stderr,"Sorting leaf list of size %d\n",nmemb);
#endif
	qsort(leaf_list,nmemb,sizeof(ParseTreeNode **),
		(int (*)(const void*,const void*))comp_tree_nodes);
}

/*
 * Removes duplicate subtrees from operator tree
 */
void shrink_tree(Optimizer *o)
{
	int leaf_list_size;
	int i;
	ParseTreeNode *dad;
	ParseTreeNode *me;
	ParseTreeNode *big_brother;
	int imleft;
	ParseTreeNode **list0;
	int list0_size;
	ParseTreeNode **list1;
	int list1_size;
	ParseTreeNode **tmp;
	ParseTreeNode *root=*o->root;
	SgrepData *sgrep=o->sgrep;

	leaf_list_size=o->tree_size*sizeof(ParseTreeNode *);
	list0=(ParseTreeNode **)sgrep_malloc(leaf_list_size);
	list1=(ParseTreeNode **)sgrep_malloc(leaf_list_size);
	list0_size=create_leaf_list(root,list0,0);
	list1_size=0;
	
	while (list0_size>1) {
		/* or and equal operators parameters can be swapped */
		for (i=0;i<list0_size;i++)
		{
		        if ((list0[i]->oper==OR ||
			     list0[i]->oper==EQUAL ||
			     list0[i]->oper==NEAR)
			    && list0[i]->label_left<list0[i]->label_right)
			{
				int tmp;
				ParseTreeNode *tree_tmp;
#ifdef DEBUG_OPTTREE
				fprintf(stderr,"swapping subtrees\n");
#endif
				tmp=list0[i]->label_left;
				list0[i]->label_left=list0[i]->label_right;
				list0[i]->label_right=tmp;
				tree_tmp=list0[i]->left;
				list0[i]->left=list0[i]->right;
				list0[i]->right=tree_tmp;
			}
		}
		
		sort_leaf_list(list0,list0_size);
#ifdef DEBUG_OPTTREE
		fprintf(stderr,"shrinking tree node list of size %d:\n",list0_size);
#endif
		big_brother=NULL;
		for (i=0;i<list0_size;i++)
		{
			me=list0[i];
			dad=me->parent;
			imleft= (dad->left==me);

			if (big_brother==NULL || comp_tree_nodes(&big_brother,&me)!=0 )
			{
				o->label_c++;
				big_brother=me;
			} else
			{	
			    o->optimized_nodes++;
				/* These don't really need to be changed,
				   It just might help catch some bugs */
				me->left=NULL;
				me->right=NULL;
				me->oper=INVALID;
				sgrep_free(me);
			}
			
			if (imleft)
			{
				dad->label_left=o->label_c;
				dad->left=big_brother;
			} else
			{
				dad->label_right=o->label_c;
				dad->right=big_brother;
			}
			assert(dad->left!=NULL);

			if (dad->label_left!=LABEL_NOTKNOWN &&
			     (dad->label_right!=LABEL_NOTKNOWN ||
			      dad->right==NULL) )
			{
				if (dad->right==NULL) dad->label_right=LABEL_NOTKNOWN;
				list1[list1_size++]=dad;
			}				
#ifdef DEBUG_OPTTREE
			fprintf(stderr," label=%-3d oper=%-15s left_label=%-3d right_label=%-3d\n",
				label_c,
				give_oper_name(big_brother->oper),
				big_brother->label_left,
				big_brother->label_right);
#endif
		}
		tmp=list0;
		list0=list1;
		list1=tmp;
		list0_size=list1_size;
		list1_size=0;
	}
	sgrep_free(list0);
	sgrep_free(list1);
}

/*
 * Creates the reference counters
 */
void create_reference_counters(ParseTreeNode *root) {
    if (root==NULL) return;	

    if (root->label_left==LABEL_CONS || root->label_left==LABEL_CHARS) {
	/* Lists with these labels should never be freed, because
	 * they are still valid when reusing parse tree
	 */
	root->refcount=-1;
    } else {
	if (root->refcount==0) {
	    /* This node is visited first time. So we need to go down too */
	    create_reference_counters(root->left);
	    create_reference_counters(root->right);
	}
	root->refcount++;
    }    
}

#ifdef DEBUG_OPTTREE
/*
 * Prints the optimized tree to stderr
 */
void print_opt_tree(ParseTreeNode *root, int depth, int label)
{
	int i;
	char line[80];
	static char *visited=NULL;
	
	if (visited==NULL)
	{
		visited=e_malloc(stats.tree_size*2); /* Should be enough */
		for (i=0;i<stats.tree_size*2;i++) visited[i]=FALSE;
	}
	if (depth>50)
	{
		fprintf(stderr,"oops, oper tree depth > 50\n");
		exit(3);
	}
	if (root->refcount>1 && !visited[label])
	{
		sprintf(line," %2d-%3d:",root->refcount,label);
	} else
	{
		if (label==0)
			line[0]=0;
		else
			sprintf(line,"         ");
	}
	for(i=0;i<depth;i++) strcat(line," ");
	if (label!=LABEL_NOTKNOWN)
	{
		if (visited[label])
		{
			fprintf(stderr,"%s^%d\n",line,label);
			return;
		}
		visited[label]=TRUE;
	}
	i=strlen(line);
	if ( root==NULL )
	{
		fprintf(stderr,"\nprint_opt_tree: got NULL node\n");
		exit(3);
	}
	if ( root->oper==PHRASE )
	{
		switch (root->label_left) {
		case LABEL_START:
			sprintf(line+i,"start");
			break;
		case LABEL_END:
			sprintf(line+i,"end");
			break;
		case LABEL_CONS:
			sprintf(line+i,"constant list");
			break;
		case LABEL_CHARS:
			sprintf(line+i,"chars");
			break;
		case LABEL_NOTKNOWN:
			sprintf(line+i,"unknown phrase type");
			break;
		default:
			sprintf(line+i,"\"%s\"",root->leaf->phrase->s);
			break;
		}
		fprintf(stderr,"%s\n",line);
		return;
	}
	if (root->oper<0 || root->oper>R_WORDS)
	{
		printf("\nprint tree: got invalid oper (%d)\n",root->oper);
		exit(3);
	}
	if (root->right!=NULL)
	{
		print_opt_tree(root->left,depth+1,root->label_left);
		sprintf(line+i,"%s",give_oper_name(root->oper));
		fprintf(stderr,"%s\n",line);
		print_opt_tree(root->right,depth+1,root->label_right);
	} else
	{
		sprintf(line+i,"%s(",give_oper_name(root->oper));
		fprintf(stderr,"%s\n",line);
		print_opt_tree(root->left,depth+1,root->label_left);
	}
}
#endif

/*
 * Performs operator tree optimizations
 */
void optimize_tree(struct SgrepStruct *sgrep,
		   ParseTreeNode **root, struct PHRASE_NODE **phrase_list)
{
    Optimizer optimizer;
    optimizer.sgrep=sgrep;
    optimizer.label_c=LABEL_FIRST;
    optimizer.root=root;
    optimizer.phrase_list=phrase_list;
    optimizer.tree_size=0;
    optimizer.optimized_nodes=0;
    optimizer.optimized_phrases=0;

    /* We need nodes parent information for optimization */
    optimizer.tree_size=add_parents(*root,NULL);
	
#ifdef DEBUG
    fprintf(stderr,"parse tree size is %d\n",stats.tree_size);
#endif
    /* Duplicate phrases are removed and their parents labeled */
    remove_duplicate_phrases(&optimizer);
	
    /* Duplicate subtrees are removed */
    shrink_tree(&optimizer);
	
    create_reference_counters(*root);
#ifdef DEBUG_OPTTREE
    print_opt_tree(*root,0,0);
#endif
    stats.parse_tree_size+=optimizer.tree_size;
    stats.optimized_phrases+=optimizer.optimized_phrases;
    stats.optimized_nodes+=optimizer.optimized_nodes;
}
