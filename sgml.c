/*
	System: Structured text retrieval tool sgrep.
	Module: sgml.c
	Author: Pekka Kilpeläinen & Jani Jaakkola
	Description: SGML/XML/HTML scanner, word tokenizer, character decoder
	Version history: Original version December 1998 by JJ & PK
	Copyright: University of Helsinki, Dept. of Computer Science
*/

#define SGREP_LIBRARY

#include <string.h>
#include <ctype.h>

#include "sgrep.h"

/* These come from the XML-specs */
#define SGML_NameChars ("-a-zA-Z0-9._:")
#define SGML_NameStartChars ("a-zA-Z_:")
#define DEFAULT_WordChars ("a-zA-Z")

#define IN_CLIST(LIST,CHAR) ( \
    ( (LIST)->bitmap[(CHAR)/sizeof(unsigned long int)] ) & \
    ( (1UL) << ((CHAR)%sizeof(unsigned long int)) ) )
#define ADD_CLIST(LIST,CHAR) ( \
    ((LIST)->bitmap[(CHAR)/sizeof(unsigned long int)]) |= \
    ( (1UL) << ((CHAR)%sizeof(unsigned long int)) ) )

typedef struct CharacterListStruct {
    unsigned long int bitmap[65536/sizeof(unsigned long int)];
    SgrepData *sgrep;
} CharacterList;

/* FIXME: check for string length */
#define MAX_TERM_SIZE 256
#define TERM_PUSH(STRING,CHAR) do { \
if (string_len(STRING)<MAX_TERM_SIZE) {string_push((STRING),(CHAR)); } \
      } while (0);

/*
 * datatypes for the SGML-scanner
 */

/*
 * Implementation of a simple SGML scanner starts here
 * (simple finite automaton)
 */
/* FIXME: index.c has a different name for same constant */
enum SGMLState { SGML_PCDATA, SGML_WORD, 
		 SGML_ENTITY_OPEN,SGML_ENTITY,SGML_PCDATA_ENTITY,
		 SGML_WORD_ENTITY,
		 SGML_CHARACTER_REFERENCE_OPEN,
		 SGML_DECIMAL_CHARACTER_REFERENCE,
		 SGML_HEX_CHARACTER_REFERENCE,
		 SGML_CHARACTER_REFERENCE_CLOSE,		 
		 SGML_STAGO, SGML_GI, SGML_W_ATTNAME, 
                 SGML_ATTNAME,
                 SGML_W_ATTEQUAL, SGML_W_ATTVALUE, 
		 SGML_ATTVALUE, SGML_ATTVALUE_DQUOTED, 
		 SGML_ATTVALUE_SQUOTED, SGML_ATTRIBUTE_END,
		 SGML_STAGC, SGML_END_TAG, SGML_W_ETAGC,
		 SGML_DECLARATION_START,SGML_DOCTYPE_DECLARATION,
		 SGML_COMMENT_START, SGML_COMMENT, SGML_COMMENT_WORD,
		 SGML_COMMENT_END1, SGML_COMMENT_END2,
		 SGML_PI, SGML_PI_END,
		 SGML_MARKED_SECTION_START, SGML_MARKED_SECTION_START2,
		 SGML_CDATA_MARKED_SECTION, SGML_CDATA_MARKED_SECTION_WORD,
		 SGML_CDATA_MARKED_SECTION_END1,
		 SGML_CDATA_MARKED_SECTION_END2,
		 SGML_DOCTYPE, SGML_DOCTYPE_EXTERNAL,
		 SGML_DOCTYPE_PUBLIC, SGML_DOCTYPE_SYSTEM,
		 SGML_WAITING_LITERAL,
		 SGML_LITERAL_START,SGML_LITERAL_SQUOTED,SGML_LITERAL_DQUOTED,
		 SGML_DOCTYPE_PUBLIC_ID_START, SGML_DOCTYPE_PUBLIC_ID,
		 SGML_DOCTYPE_SYSTEM_ID_START, SGML_DOCTYPE_SYSTEM_ID,
		 SGML_DOCTYPE_INTERNAL_START,
		 SGML_DOCTYPE_INTERNAL,
		 SGML_INTERNAL_DECLARATION_START1,
		 SGML_INTERNAL_DECLARATION_START2,
		 SGML_PEREFERENCE,
		 SGML_INTERNAL_DECLARATION_NAME,
		 SGML_ENTITY_DECLARATION,
		 SGML_ENTITY_DECLARATION_NAME,
		 SGML_ENTITY_DEFINITION,
		 SGML_ENTITY_DEFINITION_TYPE,
		 SGML_LITERAL_ENTITY,
		 SGML_GENERAL_ENTITY_DEFINITION_DQUOTED,
		 SGML_GENERAL_ENTITY_DEFINITION_SQUOTED,
		 SGML_ENTITY_DEFINITION_PUBLIC_ID,
		 SGML_WAITING_ENTITY_DEFINITION_SYSTEM_ID,
		 SGML_ENTITY_DEFINITION_SYSTEM_ID,
		 SGML_ENTITY_DEFINITION_NDATA,
		 SGML_ENTITY_DEFINITION_NDATA2,
		 SGML_ENTITY_DEFINITION_NDATA_NAME,
		 SGML_ENTITY_DEFINITION_END,
		 SGML_ELEMENT_TYPE_DECLARATION,
		 SGML_ATTLIST_DECLARATION,
		 SGML_NOTATION_DECLARATION,
		 SGML_DOCTYPE_END,
		 SGML_RESERVED_WORD
                };

typedef struct ElementStackStruct {
    char *gi;
    int start;
    int end;
    struct ElementStackStruct *prev;
} ElementStack;

enum EncoderState { 
    EIGHT_BIT, 
    UTF8_1, UTF8_2, UTF8_3_1, UTF8_3_2,
    UTF16_1,
    UTF16_BIG_START,UTF16_BIG,
    UTF16_SMALL_START,UTF16_SMALL
};

typedef struct EncoderStruct {
    enum EncoderState estate;
    int char1;
    int char2;
    int prev;
} Encoder;


struct SGMLScannerStruct {
    SgrepData *sgrep;
    FileList *file_list;
    int file_num;

    /* The Encoder */
    Encoder encoder;

    /* Scanner "configuration" */
    ScannerType type;
    CharacterList *name_start_chars;
    CharacterList *name_chars;
    CharacterList *word_chars;
    CharacterList *indexed_chars;
    int ignore_case;
    int include_system_entities;

    /* Maintaining the element stack */
    int maintain_element_stack;
    ElementStack *top;
    RegionList *element_list;
    
    /* Scanner state */
    int parse_errors;
    struct PHRASE_NODE *phrase_list;
    int words;
    int word_end;
    SgrepString *word;

    /* Start and end tag */
    int tags;
    SgrepString *gi;

    /* Attributes */
    int anames;
    SgrepString *aname;
    int avals;
    SgrepString *aval;

    /* Comments */
    int comments;
    int comment_words;
    SgrepString *comment_word;

    int markeds;
    
    int doctypes;
    int doctype_declarations;
    int internal_declarations;

    int entity_has_systemid;
    int entity_is_ndata;
    int entitys; /* Start of entity reference */
    int character_reference;

    SgrepString *name;

    int name2s;
    SgrepString *name2;
    
    int literals;
    SgrepString *literal;

    int publici;
    int systemi;

    SgrepString *pi;

    enum SGMLState state;
    
    /* This isn't a real stack of context free language parser;
     * it's just a trick for some state reuse */
#define SGML_SCANNER_STACK_SIZE 10
    enum SGMLState state_stack[SGML_SCANNER_STACK_SIZE];
    int state_stack_ptr;

    void (*entry)(struct SGMLScannerStruct *state,
		  const char *str, int start, int end);
    void *data;

    int failed;
};

/*
 * The XML character class definitions. These come straight from the
 * XML spesification
 */

const char *XML_BaseChar=
"\\#x0041-\\#x005A\\#x0061-\\#x007A\\#x00C0-\\#x00D6"
"\\#x00D8-\\#x00F6\\#x00F8-\\#x00FF\\#x0100-\\#x0131"
"\\#x0134-\\#x013E\\#x0141-\\#x0148\\#x014A-\\#x017E"
"\\#x0180-\\#x01C3\\#x01CD-\\#x01F0\\#x01F4-\\#x01F5"
"\\#x01FA-\\#x0217\\#x0250-\\#x02A8\\#x02BB-\\#x02C1\\#x0386"
"\\#x0388-\\#x038A\\#x038C\\#x038E-\\#x03A1\\#x03A3-\\#x03CE"
"\\#x03D0-\\#x03D6\\#x03DA\\#x03DC\\#x03DE\\#x03E0"
"\\#x03E2-\\#x03F3\\#x0401-\\#x040C\\#x040E-\\#x044F"
"\\#x0451-\\#x045C\\#x045E-\\#x0481\\#x0490-\\#x04C4"
"\\#x04C7-\\#x04C8\\#x04CB-\\#x04CC\\#x04D0-\\#x04EB"
"\\#x04EE-\\#x04F5\\#x04F8-\\#x04F9\\#x0531-\\#x0556\\#x0559"
"\\#x0561-\\#x0586\\#x05D0-\\#x05EA\\#x05F0-\\#x05F2"
"\\#x0621-\\#x063A\\#x0641-\\#x064A\\#x0671-\\#x06B7"
"\\#x06BA-\\#x06BE\\#x06C0-\\#x06CE\\#x06D0-\\#x06D3\\#x06D5"
"\\#x06E5-\\#x06E6\\#x0905-\\#x0939\\#x093D\\#x0958-\\#x0961"
"\\#x0985-\\#x098C\\#x098F-\\#x0990\\#x0993-\\#x09A8"
"\\#x09AA-\\#x09B0\\#x09B2\\#x09B6-\\#x09B9\\#x09DC-\\#x09DD"
"\\#x09DF-\\#x09E1\\#x09F0-\\#x09F1\\#x0A05-\\#x0A0A"
"\\#x0A0F-\\#x0A10\\#x0A13-\\#x0A28\\#x0A2A-\\#x0A30"
"\\#x0A32-\\#x0A33\\#x0A35-\\#x0A36\\#x0A38-\\#x0A39"
"\\#x0A59-\\#x0A5C\\#x0A5E\\#x0A72-\\#x0A74\\#x0A85-\\#x0A8B"
"\\#x0A8D\\#x0A8F-\\#x0A91\\#x0A93-\\#x0AA8\\#x0AAA-\\#x0AB0"
"\\#x0AB2-\\#x0AB3\\#x0AB5-\\#x0AB9\\#x0ABD\\#x0AE0"
"\\#x0B05-\\#x0B0C\\#x0B0F-\\#x0B10\\#x0B13-\\#x0B28"
"\\#x0B2A-\\#x0B30\\#x0B32-\\#x0B33\\#x0B36-\\#x0B39\\#x0B3D"
"\\#x0B5C-\\#x0B5D\\#x0B5F-\\#x0B61\\#x0B85-\\#x0B8A"
"\\#x0B8E-\\#x0B90\\#x0B92-\\#x0B95\\#x0B99-\\#x0B9A\\#x0B9C"
"\\#x0B9E-\\#x0B9F\\#x0BA3-\\#x0BA4\\#x0BA8-\\#x0BAA"
"\\#x0BAE-\\#x0BB5\\#x0BB7-\\#x0BB9\\#x0C05-\\#x0C0C"
"\\#x0C0E-\\#x0C10\\#x0C12-\\#x0C28\\#x0C2A-\\#x0C33"
"\\#x0C35-\\#x0C39\\#x0C60-\\#x0C61\\#x0C85-\\#x0C8C"
"\\#x0C8E-\\#x0C90\\#x0C92-\\#x0CA8\\#x0CAA-\\#x0CB3"
"\\#x0CB5-\\#x0CB9\\#x0CDE\\#x0CE0-\\#x0CE1\\#x0D05-\\#x0D0C"
"\\#x0D0E-\\#x0D10\\#x0D12-\\#x0D28\\#x0D2A-\\#x0D39"
"\\#x0D60-\\#x0D61\\#x0E01-\\#x0E2E\\#x0E30\\#x0E32-\\#x0E33"
"\\#x0E40-\\#x0E45\\#x0E81-\\#x0E82\\#x0E84\\#x0E87-\\#x0E88"
"\\#x0E8A\\#x0E8D\\#x0E94-\\#x0E97\\#x0E99-\\#x0E9F"
"\\#x0EA1-\\#x0EA3\\#x0EA5\\#x0EA7\\#x0EAA-\\#x0EAB"
"\\#x0EAD-\\#x0EAE\\#x0EB0\\#x0EB2-\\#x0EB3\\#x0EBD"
"\\#x0EC0-\\#x0EC4\\#x0F40-\\#x0F47\\#x0F49-\\#x0F69"
"\\#x10A0-\\#x10C5\\#x10D0-\\#x10F6\\#x1100\\#x1102-\\#x1103"
"\\#x1105-\\#x1107\\#x1109\\#x110B-\\#x110C\\#x110E-\\#x1112"
"\\#x113C\\#x113E\\#x1140\\#x114C\\#x114E\\#x1150"
"\\#x1154-\\#x1155\\#x1159\\#x115F-\\#x1161\\#x1163\\#x1165"
"\\#x1167\\#x1169\\#x116D-\\#x116E\\#x1172-\\#x1173\\#x1175"
"\\#x119E\\#x11A8\\#x11AB\\#x11AE-\\#x11AF\\#x11B7-\\#x11B8"
"\\#x11BA\\#x11BC-\\#x11C2\\#x11EB\\#x11F0\\#x11F9"
"\\#x1E00-\\#x1E9B\\#x1EA0-\\#x1EF9\\#x1F00-\\#x1F15"
"\\#x1F18-\\#x1F1D\\#x1F20-\\#x1F45\\#x1F48-\\#x1F4D"
"\\#x1F50-\\#x1F57\\#x1F59\\#x1F5B\\#x1F5D\\#x1F5F-\\#x1F7D"
"\\#x1F80-\\#x1FB4\\#x1FB6-\\#x1FBC\\#x1FBE\\#x1FC2-\\#x1FC4"
"\\#x1FC6-\\#x1FCC\\#x1FD0-\\#x1FD3\\#x1FD6-\\#x1FDB"
"\\#x1FE0-\\#x1FEC\\#x1FF2-\\#x1FF4\\#x1FF6-\\#x1FFC\\#x2126"
"\\#x212A-\\#x212B\\#x212E\\#x2180-\\#x2182\\#x3041-\\#x3094"
"\\#x30A1-\\#x30FA\\#x3105-\\#x312C\\#xAC00-\\#xD7A3"
;

const char *XML_Ideographic=
"\\#x4E00-\\#x9FA5\\#x3007\\#x3021-\\#x3029"
;

const char *XML_CombiningChar=
"\\#x0300-\\#x0345\\#x0360-\\#x0361\\#x0483-\\#x0486"
"\\#x0591-\\#x05A1\\#x05A3-\\#x05B9\\#x05BB-\\#x05BD\\#x05BF"
"\\#x05C1-\\#x05C2\\#x05C4\\#x064B-\\#x0652\\#x0670"
"\\#x06D6-\\#x06DC\\#x06DD-\\#x06DF\\#x06E0-\\#x06E4"
"\\#x06E7-\\#x06E8\\#x06EA-\\#x06ED\\#x0901-\\#x0903\\#x093C"
"\\#x093E-\\#x094C\\#x094D\\#x0951-\\#x0954\\#x0962-\\#x0963"
"\\#x0981-\\#x0983\\#x09BC\\#x09BE\\#x09BF\\#x09C0-\\#x09C4"
"\\#x09C7-\\#x09C8\\#x09CB-\\#x09CD\\#x09D7\\#x09E2-\\#x09E3"
"\\#x0A02\\#x0A3C\\#x0A3E\\#x0A3F\\#x0A40-\\#x0A42"
"\\#x0A47-\\#x0A48\\#x0A4B-\\#x0A4D\\#x0A70-\\#x0A71"
"\\#x0A81-\\#x0A83\\#x0ABC\\#x0ABE-\\#x0AC5\\#x0AC7-\\#x0AC9"
"\\#x0ACB-\\#x0ACD\\#x0B01-\\#x0B03\\#x0B3C\\#x0B3E-\\#x0B43"
"\\#x0B47-\\#x0B48\\#x0B4B-\\#x0B4D\\#x0B56-\\#x0B57"
"\\#x0B82-\\#x0B83\\#x0BBE-\\#x0BC2\\#x0BC6-\\#x0BC8"
"\\#x0BCA-\\#x0BCD\\#x0BD7\\#x0C01-\\#x0C03\\#x0C3E-\\#x0C44"
"\\#x0C46-\\#x0C48\\#x0C4A-\\#x0C4D\\#x0C55-\\#x0C56"
"\\#x0C82-\\#x0C83\\#x0CBE-\\#x0CC4\\#x0CC6-\\#x0CC8"
"\\#x0CCA-\\#x0CCD\\#x0CD5-\\#x0CD6\\#x0D02-\\#x0D03"
"\\#x0D3E-\\#x0D43\\#x0D46-\\#x0D48\\#x0D4A-\\#x0D4D\\#x0D57"
"\\#x0E31\\#x0E34-\\#x0E3A\\#x0E47-\\#x0E4E\\#x0EB1"
"\\#x0EB4-\\#x0EB9\\#x0EBB-\\#x0EBC\\#x0EC8-\\#x0ECD"
"\\#x0F18-\\#x0F19\\#x0F35\\#x0F37\\#x0F39\\#x0F3E\\#x0F3F"
"\\#x0F71-\\#x0F84\\#x0F86-\\#x0F8B\\#x0F90-\\#x0F95\\#x0F97"
"\\#x0F99-\\#x0FAD\\#x0FB1-\\#x0FB7\\#x0FB9\\#x20D0-\\#x20DC"
"\\#x20E1\\#x302A-\\#x302F\\#x3099\\#x309A"
;

const char *XML_Digit=
"\\#x0030-\\#x0039\\#x0660-\\#x0669\\#x06F0-\\#x06F9"
"\\#x0966-\\#x096F\\#x09E6-\\#x09EF\\#x0A66-\\#x0A6F"
"\\#x0AE6-\\#x0AEF\\#x0B66-\\#x0B6F\\#x0BE7-\\#x0BEF"
"\\#x0C66-\\#x0C6F\\#x0CE6-\\#x0CEF\\#x0D66-\\#x0D6F"
"\\#x0E50-\\#x0E59\\#x0ED0-\\#x0ED9\\#x0F20-\\#x0F29"
;

const char *XML_Extender=
"\\#x00B7\\#x02D0\\#x02D1\\#x0387\\#x0640\\#x0E46\\#x0EC6"
"\\#x3005\\#x3031-\\#x3035\\#x309D-\\#x309E\\#x30FC-\\#x30FE"
;

/*
 * Creates a new empty character list
 */
CharacterList *new_character_list(SgrepData *sgrep) {
    CharacterList *a;
    a=sgrep_new(CharacterList);
    memset(a,0,sizeof(CharacterList));
    a->sgrep=sgrep;
    return a;
}

/*
 * Parses a given character list string adding them to a CharacterList 
 */
void character_list_add(CharacterList *a,const char *l) {
    int i;
    const unsigned char *list=(const unsigned char *)l;
    int previous;
    int expand_from;
    int current;
    SGREPDATA(a);

    previous=-1;
    expand_from=-1;
    i=0;
    while(list[i]) {
	current=list[i];
	i++;
	if (current=='\\') {
	    if (list[i]=='-') {
		/* Escape also \- */
		i++;
		current='-';
	    } else {
		current=expand_backslash_escape(sgrep,list,&i);
	    }
	} else if (current=='-' && i>1 && expand_from==-1) {
	    /* Mark the requirement to expand in next iteration */
	    expand_from=previous;
	    continue;
	}
	
	if (expand_from>=0 && current>=0) {
	    /* A region */
	    int j;
	    for(j=expand_from;j<=current;j++) {
		ADD_CLIST(a,j);
	    }
	} else if (current>=0) {
	    ADD_CLIST(a,current);
	}
	expand_from=-1;
	previous=current;
	current=-1;
    }
    if (expand_from>=0) {
	sgrep_error(sgrep,"Character list '%s' contains a region with no endpoint\n",
		    list);
    }
}

void pop_elements_to(SGMLScanner *state,
			    struct ElementStackStruct *p);


/* FIXME: needs hashing for speed */
void sgml_add_entry_to_gclist(SGMLScanner *state,
			      const char *phrase,int start, int end) {
    struct PHRASE_NODE *n;
    for(n=state->phrase_list;n!=NULL;n=n->next) {
	if (n->phrase->s[n->phrase->length-1]=='*') {
	    /* Wildcard */
	    if (strncmp(n->phrase->s,phrase,n->phrase->length-1)==0) {
		add_region(n->regions,start,end);
	    
	    }
	} else if (strcmp(n->phrase->s,phrase)==0) {
	    add_region(n->regions,start,end);
	}
    }
}

void sgml_add_entry_to_index(SGMLScanner *state,
			     const char *phrase,
			     int start, int end) {
    if (phrase[0]=='@') {
	add_region(state->element_list,start,end);
    } else {
	if (add_region_to_index((struct IndexWriterStruct *)state->data,
				phrase,start,end)==SGREP_ERROR) {
	    state->failed=1;
	}
    }
}

void reset_encoder(SGMLScanner *sgmls, Encoder *encoder) {
    SGREPDATA(sgmls);

    switch(sgrep->default_encoding) {
    case ENCODING_GUESS:
	switch(sgmls->type) {
	case SGML_SCANNER:
	    encoder->estate=EIGHT_BIT;
	    break;
	case XML_SCANNER:
	    encoder->estate=UTF8_1;
	    break;
	case TEXT_SCANNER:
	    encoder->estate=EIGHT_BIT;
	    break;
	}
	break;
    case ENCODING_8BIT:
	encoder->estate=EIGHT_BIT;
	break;
    case ENCODING_UTF8:
	encoder->estate=UTF8_1;
	break;
    case ENCODING_UTF16:
	encoder->estate=UTF8_1;
	break;
    }
    encoder->prev=-1;
}

SGMLScanner *new_sgml_scanner_common(SgrepData *sgrep, FileList *file_list) {
    SGMLScanner *scanner;
    scanner=sgrep_new(SGMLScanner);
    scanner->sgrep=sgrep;
    scanner->file_list=file_list;
    scanner->file_num=-1;
    scanner->state_stack_ptr=0;

    scanner->maintain_element_stack=1;
    scanner->top=NULL;
    scanner->element_list=NULL;

    scanner->word_chars=new_character_list(sgrep);
    switch(sgrep->scanner_type) {
    case SGML_SCANNER:
	scanner->name_start_chars=new_character_list(sgrep);
	character_list_add(scanner->name_start_chars,SGML_NameStartChars);
	scanner->name_chars=new_character_list(sgrep);
	character_list_add(scanner->name_chars,SGML_NameChars);
	break;
    case XML_SCANNER:
	/* NameStart characters */
	scanner->name_start_chars=new_character_list(sgrep);
	character_list_add(scanner->name_start_chars,XML_BaseChar);
	character_list_add(scanner->name_start_chars,XML_Ideographic);
	character_list_add(scanner->name_start_chars,SGML_NameStartChars);
	/* Name characters */
	scanner->name_chars=new_character_list(sgrep);
	character_list_add(scanner->name_chars,XML_BaseChar);
	character_list_add(scanner->name_chars,XML_Ideographic);
	character_list_add(scanner->name_chars,SGML_NameChars);	
	break;
    case TEXT_SCANNER:
	scanner->name_start_chars=NULL;
	scanner->name_chars=NULL;
	break;
    }
    if (sgrep->word_chars) {
	character_list_add(scanner->word_chars,sgrep->word_chars);
    } else {
        character_list_add(scanner->word_chars,XML_BaseChar);
	character_list_add(scanner->word_chars,XML_Ideographic);
    }
    scanner->parse_errors=0;

    scanner->type=sgrep->scanner_type;
    scanner->ignore_case=sgrep->ignore_case;
    scanner->include_system_entities=sgrep->include_system_entities;

    scanner->state=SGML_PCDATA;

    scanner->gi=new_string(sgrep,MAX_TERM_SIZE);
    scanner->word=new_string(sgrep,MAX_TERM_SIZE);
    TERM_PUSH(scanner->word,'w');
    scanner->name2=new_string(sgrep,MAX_TERM_SIZE);
    scanner->comment_word=new_string(sgrep,MAX_TERM_SIZE);
    scanner->name=new_string(sgrep,MAX_TERM_SIZE);
    scanner->literal=new_string(sgrep,MAX_TERM_SIZE);
    string_cat(scanner->literal,"xxx");
    scanner->aname=new_string(sgrep,MAX_TERM_SIZE);
    TERM_PUSH(scanner->aname,'a');
    scanner->aval=new_string(sgrep,MAX_TERM_SIZE);
    TERM_PUSH(scanner->aval,'v');
    scanner->pi=new_string(sgrep,MAX_TERM_SIZE);
    TERM_PUSH(scanner->pi,'?');
    scanner->failed=0;

    reset_encoder(scanner,&scanner->encoder);
    return scanner;
}

SGMLScanner *new_sgml_phrase_scanner(SgrepData *sgrep,
				     FileList *file_list,
				      struct PHRASE_NODE *list) {    
    SGMLScanner *scanner;
    scanner=new_sgml_scanner_common(sgrep,file_list);
    scanner->phrase_list=list;
    scanner->entry=sgml_add_entry_to_gclist;
    scanner->data=NULL;
    return scanner;
}

    
SGMLScanner *new_sgml_index_scanner(SgrepData *sgrep,
				    FileList *file_list,
				    struct IndexWriterStruct *writer) {    
    SGMLScanner *scanner;
    scanner=new_sgml_scanner_common(sgrep,file_list);
    scanner->phrase_list=NULL;
    scanner->element_list=new_region_list(sgrep);
    list_set_sorted(scanner->element_list,NOT_SORTED);
    scanner->element_list->nested=1;
    scanner->entry=sgml_add_entry_to_index;
    scanner->data=writer;
    return scanner;
}

void delete_sgml_scanner(SGMLScanner *s) {
    SgrepData *sgrep=s->sgrep;
    /* Empty the element stack if there is one */
    pop_elements_to(s,NULL);
    if (s->element_list) {
	delete_region_list(s->element_list);
    }
    delete_string(s->word);
    delete_string(s->name2);
    delete_string(s->comment_word);
    delete_string(s->gi);
    delete_string(s->aname);
    delete_string(s->aval);
    delete_string(s->name);
    delete_string(s->literal);
    delete_string(s->pi);
    if (s->name_start_chars) sgrep_free(s->name_start_chars);
    if (s->name_chars) sgrep_free(s->name_chars);
    sgrep_free(s->word_chars);
    sgrep_free(s);
}


void push_state(SGMLScanner *scanner, enum SGMLState state) {
    assert(scanner->state_stack_ptr<SGML_SCANNER_STACK_SIZE);
    scanner->state_stack[scanner->state_stack_ptr++]=state;
}

enum SGMLState pop_state(SGMLScanner *scanner) {
    assert(scanner->state_stack_ptr>0);
    return scanner->state_stack[--scanner->state_stack_ptr];
}



#define SGML_ENTRY(QUERY,NAME,RAW_NAME,START,END) \
do { if (sgrep->sgml_debug) sgrep_error(sgrep,"%s(\"%s\"):%s:(%d,%d)\n",(QUERY),(NAME),(RAW_NAME),(START),(END)); \
if ((START)<=(END)) state->entry(state,(char *)(RAW_NAME),(START),(END)); } while (0)

void pop_elements_to(SGMLScanner *state,ElementStack *p) {
    ElementStack *q;
    SGREPDATA(state);
    assert(p==NULL || state->top);
    /* Element is in the stack */
    q=state->top;
    while(p!=q) {
	/* All elements in the stack not having an end tag
	 * are considered as empty. Sad but true */
	state->top=q->prev;
	SGML_ENTRY("elements","","@elements",q->start,q->end);
	/* fprintf(stderr,"<%s/>\n",q->gi); */
	sgrep_free(q->gi);
	sgrep_free(q);
	q=state->top;
    }
}

/*
 * If you think that this function is dull to read, I can assure that is was
 * even duller to write
 */
void parse_xml_declaration(SGMLScanner *scanner) {
    SGREPDATA(scanner);
    const char *version="version";
    const char *encoding="encoding";
    const unsigned char *ptr=string_to_char(scanner->pi)+4;
    SgrepString *encoding_name;
    int quote_ch;

    encoding_name=new_string(sgrep,MAX_TERM_SIZE);
    /* Whitespace */
    while(*ptr && isspace(*ptr)) ptr++;

    /* "version" */
    while(*ptr && *ptr==*version) {
	ptr++;
	version++;
    }
    if (*version) goto error;
    /* Whitespace */
    while(*ptr && isspace(*ptr)) ptr++;
    /* "=" */
    if (*ptr!='=') goto error;
    ptr++;
    /* Whitespace */
    while(*ptr && isspace(*ptr)) ptr++;
    /* quote */
    if (*ptr!='\'' && *ptr!='\"') goto error;
    quote_ch=*(ptr++);
    /* Ignores version */
    while(*ptr && *ptr!=quote_ch) ptr++;
    if (*ptr!=quote_ch) goto error;
    ptr++;

    /* Whitespace */
    while(*ptr && isspace(*ptr)) ptr++;
    if (!*ptr) {
	delete_string(encoding_name);
	return;
    }

    /* "encoding" */
    while(*ptr && *ptr==*encoding) {
	ptr++;
	encoding++;
    }
    if (*encoding) goto error;
    /* Whitespace */
    while(*ptr && isspace(*ptr)) ptr++;
    /* "=" */
    if (*ptr!='=') goto error;
    ptr++;
    /* Whitespace */
    while(*ptr && isspace(*ptr)) ptr++;

    /* quote */
    if (*ptr!='\'' && *ptr!='\"') goto error;
    quote_ch=*(ptr++);
    
    /* Scan the encoding */
    while(*ptr && *ptr!=quote_ch) {
	string_push(encoding_name,*ptr);
	ptr++;
    }
    if (*ptr!=quote_ch) goto error;
    ptr++;
    /* Ignore the rest of declaration, whatever there is */

    if (sgrep->sgml_debug) {
	sgrep_progress(sgrep,"encoding=%s\n",string_to_char(encoding_name));
    }

    /* If we have been given the encoding, ignore the encoding parameter
     */
    if (sgrep->default_encoding==ENCODING_GUESS) {
	string_tolower(encoding_name,0);
	if (strcmp(string_to_char(encoding_name),"iso-8859-1")==0 ||
	    strcmp(string_to_char(encoding_name),"us-ascii")==0) {
	    scanner->encoder.estate=EIGHT_BIT;
	} else if (strcmp(string_to_char(encoding_name),"utf-8")==0) {
	    scanner->encoder.estate=UTF8_1;
	} else if (strcmp(string_to_char(encoding_name),"utf-16")==0) {
	    if (scanner->encoder.estate==UTF8_1 || 
		scanner->encoder.estate==EIGHT_BIT) {
		sgrep_error(sgrep,"File '%s': utf-16 encoding given in 8-bit encoding declaration?",
		flist_name(scanner->file_list,scanner->file_num));
	    }
	} else {	
	    sgrep_error(sgrep,"File '%s':Unknown encoding '%s'. Using default.\n",
			flist_name(scanner->file_list,scanner->file_num),
			string_to_char(encoding_name));	
	    reset_encoder(scanner,&scanner->encoder);
	}		    
    }
    delete_string(encoding_name);
    return;

 error:
    delete_string(encoding_name);
    scanner->parse_errors++;
    sgrep_error(sgrep,"File '%s':Parse error in XML-declaration.\n",
		flist_name(scanner->file_list,scanner->file_num));    
}

void sgml_found(SGMLScanner *state,enum SGMLState s,int end_index) {
    SGREPDATA(state);
    end_index--;

    switch(s) {
    case SGML_WORD:
    case SGML_WORD_ENTITY:
    case SGML_CDATA_MARKED_SECTION_WORD:
	assert(string_to_char(state->word)[0]=='w');
	if (state->ignore_case) {
	    string_tolower(state->word,1);
	}
	SGML_ENTRY("word",
		   string_escaped(state->word)+1,
		   string_to_char(state->word),
		   state->words,end_index);
	break;
	
    case SGML_ENTITY:
	assert(string_to_char(state->name)[0]=='&');
	SGML_ENTRY("entity",
		   string_escaped(state->name)+1,
		   string_to_char(state->name),
		   state->entitys,end_index);
	break;

    case SGML_STAGC:
	if (state->type!=XML_SCANNER) {
	    string_toupper(state->gi,1);
	}
	SGML_ENTRY("stag",
		   string_escaped(state->gi)+1,
		   string_to_char(state->gi),
		   state->tags,end_index);
	if (state->maintain_element_stack) {
	    /* Push to element stack */
	    ElementStack *e=sgrep_new(ElementStack);
	    e->gi=sgrep_strdup(string_to_char(state->gi)+1);
	    e->start=state->tags;
	    e->end=end_index;
	    e->prev=state->top;
	    state->top=e;
	}
	break;

    case SGML_ATTVALUE:
    case SGML_ATTVALUE_DQUOTED:
    case SGML_ATTVALUE_SQUOTED:
	SGML_ENTRY("attvalue",
		   string_escaped(state->aval)+1,
		   string_to_char(state->aval),
		   state->avals,end_index);
	break;

    case SGML_ATTRIBUTE_END:
	if (state->type!=XML_SCANNER) {
	    string_toupper(state->aname,1);
	}
	SGML_ENTRY("attribute",
		   string_escaped(state->aname)+1,
		   string_to_char(state->aname),
		   state->anames,end_index);
	break;
	
    case SGML_W_ETAGC:
	if (state->type!=XML_SCANNER) {
	    string_toupper(state->gi,1);
	}
	SGML_ENTRY("etag",
		   string_escaped(state->gi)+1,
		   string_to_char(state->gi),
		   state->tags,end_index);
	if (state->maintain_element_stack) {
	    /* First check that the element is on the stack */
	    ElementStack *p=state->top;
	    while(p && strcmp(string_to_char(state->gi)+1,p->gi)!=0) {
		p=p->prev;
	    }
	    if (p) {
		/* Take elements until p is in top */
		pop_elements_to(state,p);
		/* Pop p */
		state->top=p->prev;
		SGML_ENTRY("elements","","@elements",p->start,end_index);
		/* fprintf(stderr,"<%s>..</%s>\n",p->gi,p->gi);*/
		sgrep_free(p->gi);
		sgrep_free(p);
	    }
	}
	break;

    case SGML_COMMENT_WORD:
	if (state->ignore_case) {
	    string_tolower(state->comment_word,1);
	}
	SGML_ENTRY("comment_word",
		   string_escaped(state->comment_word)+1,
		   string_to_char(state->comment_word),
		   state->comment_words,end_index);
	break;
	   
    case SGML_COMMENT_END2:
	SGML_ENTRY("comment",(const unsigned char *)"",
		   (const unsigned char *)"-",
		   state->comments,end_index);
	break;

    case SGML_PI:
    case SGML_PI_END:
	SGML_ENTRY("pi",
		   string_escaped(state->pi)+1,
		   string_to_char(state->pi),
		   state->tags,end_index);
	if (state->type==XML_SCANNER &&
	    toupper(string_to_char(state->pi)[1])=='X' &&
	    toupper(string_to_char(state->pi)[2])=='M' &&
	    toupper(string_to_char(state->pi)[3])=='L') {
	    parse_xml_declaration(state);
	}
	break;

    case SGML_CDATA_MARKED_SECTION_END2:
	SGML_ENTRY("cdata",(const unsigned char *)"",
		   (const unsigned char *)"[CDATA",
		   state->markeds,end_index);
	break;

    case SGML_DOCTYPE:
	assert(string_to_char(state->name)[0]=='d' &&
	       string_to_char(state->name)[1]=='n');
	if (state->type!=XML_SCANNER) {
	    string_toupper(state->name,2);
	}
	SGML_ENTRY("doctype",
		   string_escaped(state->name)+2,
		   string_to_char(state->name),
		   state->doctypes, end_index);
	/* Empty the element stack */
	pop_elements_to(state,NULL);
	break;

    case SGML_DOCTYPE_PUBLIC_ID:
	state->literal->s[1]='d';
	state->literal->s[2]='p';
	SGML_ENTRY("doctype_pid",
		   string_escaped(state->literal)+3,
		   string_to_char(state->literal)+1,
		   state->literals,end_index);
	break;
	
    case SGML_DOCTYPE_SYSTEM_ID:
	state->literal->s[1]='d';
	state->literal->s[2]='s';
	SGML_ENTRY("doctype_sid",
		   string_escaped(state->literal)+3,
		   string_to_char(state->literal)+1,
		   state->literals,end_index);
	break;

    case SGML_DOCTYPE_END:
	SGML_ENTRY("prologs",(const unsigned char *)"d",
		   (const unsigned char *)"d!",
		   state->doctype_declarations, end_index);
	break;

	/* FIXME: add the literal instead of it's name */
    case SGML_GENERAL_ENTITY_DEFINITION_DQUOTED:
    case SGML_GENERAL_ENTITY_DEFINITION_SQUOTED:
	assert(string_to_char(state->name)[0]=='!' &&
	       string_to_char(state->name)[1]=='e');
	state->name->s[2]='l';
	SGML_ENTRY("entity_literal",
		   string_escaped(state->name)+3,
		   string_to_char(state->name),
		   state->literals,end_index);
	break;

    case SGML_ENTITY_DEFINITION_END:
	assert(string_to_char(state->name)[0]=='!' &&
	       string_to_char(state->name)[1]=='e');
	state->name->s[2]='d';
	SGML_ENTRY("entity_declaration",
		   string_escaped(state->name)+3,
		   string_to_char(state->name),
		   state->internal_declarations,end_index);
	/* Check if this is an system entity reference we should include */
	if (state->entity_has_systemid && 
	    (!state->entity_is_ndata) &&
	    state->include_system_entities) {
	    const char *url=string_to_char(state->literal)+3;
	    if (!flist_exists(state->file_list, url)) {
		if (flist_add_relative(state->file_list,
				       state->file_num,
				       url)==SGREP_OK) {
		    sgrep_progress(sgrep,
				   "Including system entity '%s'\n",
				   url);
		    /* fprintf(stderr,"File list size %d\n",
		       flist_files(state->scan_buffer->file_list)); */

		} else {
		    sgrep_progress(sgrep,"Cannot include system entity '%s'\n",
				   url);
		}
	    }
	}
	break;

    case SGML_ENTITY_DEFINITION_PUBLIC_ID:
	state->literal->s[0]='!';
	state->literal->s[1]='e';
	state->literal->s[2]='p';
	SGML_ENTRY("entity_pid",
		   string_escaped(state->literal)+3,
		   string_to_char(state->literal),
		   state->literals,end_index);
	break;

    case SGML_ENTITY_DEFINITION_SYSTEM_ID:
	state->literal->s[0]='!';
	state->literal->s[1]='e';
	state->literal->s[2]='s';
	SGML_ENTRY("entity_sid",
		   string_escaped(state->literal)+3,
		   string_to_char(state->literal),
		   state->literals,end_index);
	break;

    case SGML_ENTITY_DEFINITION_NDATA_NAME:
	if (state->type!=XML_SCANNER) {
	    string_toupper(state->name2,3);
	}
	SGML_ENTRY("entity_ndata",
		   string_escaped(state->name2)+3,
		   string_to_char(state->name2),
		   state->name2s,end_index);
	break;

    case SGML_ELEMENT_TYPE_DECLARATION:
    case SGML_ATTLIST_DECLARATION:
    case SGML_NOTATION_DECLARATION:
	/* Not used */
	break;
	
    default:
	sgrep_error(sgrep,"SGML huh?\n");
	break;
    }
}

/* FIXME: remember to reset encoding */
void sgml_flush(SGMLScanner *sgmls) {
    SGREPDATA(sgmls);

    /* sgrep_progress(sgrep,"sgml_flush()\n"); */
    pop_elements_to(sgmls,NULL);
    if (sgmls->element_list && sgmls->entry==sgml_add_entry_to_index) {
	ListIterator l;
	Region r;
	struct IndexWriterStruct *writer=
	    (struct IndexWriterStruct *)sgmls->data;

	/* sgrep_progress(sgrep,"Adding element list to index\n"); */
	start_region_search(sgmls->element_list,&l);
	get_region(&l,&r);
	while(r.start!=-1) {
	    add_region_to_index(writer,"@elements",r.start,r.end);	    
	    get_region(&l,&r);
	}
	delete_region_list(sgmls->element_list);
	sgmls->element_list=new_region_list(sgrep);
	list_set_sorted(sgmls->element_list,NOT_SORTED);
	sgmls->element_list->nested=1;
    }
    reset_encoder(sgmls,&sgmls->encoder);
    sgmls->state=SGML_PCDATA;
}
    
/*
 * This could be made faster with macro magics like in James Clarks expat.
 * I hope that no one notices.
 */
int sgml_scan(SGMLScanner *scanner,
	      const unsigned char *buf, 
	      int len,
	      int start,int file_num) {
#define POS (start+i)
#define NEXT_CH do { encoder->prev=POS; ch=-1; } while(0)
#define SGML_FOUND(SCANNER,END) do { \
    sgml_found((SCANNER),state,(END)); if ((SCANNER)->failed) return SGREP_ERROR; \
} while(0)
    int i;
    int ch=-1;
    Encoder *encoder=&scanner->encoder;
    enum SGMLState state=scanner->state;
    SGREPDATA(scanner);

    if (encoder->prev==-1) encoder->prev=start;
    
    scanner->file_num=file_num;
    i=0;
    ch=-1;
    while(1) {
	if (ch==-1) {
	    /* If no more bytes, break out */
	    if (i>=len) break;
	    
	    switch (encoder->estate) {
	    case EIGHT_BIT:
		ch=buf[i++];
		break;
	    case UTF8_1:
		if (buf[i]<0x80) {
		    ch=buf[i++];
		} else if (buf[i]<0xc0) {
		    ch=' ';
		    sgrep_error(sgrep,"UTF8 decoding error (<0xc0)\n");
		    scanner->parse_errors++;
		    i++;
		} else if (buf[i]<0xe0) {
		    encoder->estate=UTF8_2;
		    encoder->char1=buf[i];
		    i++;
		    continue;
		} else if (buf[i]<0xf0) {
		    encoder->estate=UTF8_3_1;
		    encoder->char1=buf[i];
		    i++;
		    continue;
		} else if (buf[i]==0xfe) {
		    encoder->estate=UTF16_BIG_START;
		    i++;
		    continue;
		} else if (buf[i]==0xff) {
		    encoder->estate=UTF16_SMALL_START;
		    i++;
		    continue;
		} else {
		    ch=' ';
		    sgrep_error(sgrep,"UTF8 decoding error (%d>=0xf0)\nn",
				buf[i]);
		    scanner->parse_errors++;
		    i++;
		}
		break;
	    case UTF8_2:
		if (buf[i]>=0x80 && buf[i]<=0xbf) {
		    ch=((encoder->char1&0x1f)<<6) | (buf[i]&0x3f);
		    encoder->estate=UTF8_1;
		    i++;
		} else {
		    ch=' ';
		    sgrep_error(sgrep,"UTF8 decoding error 2 (%d<0x80 || >0xbf)\n",
				buf[i]);
		    scanner->parse_errors++;
		    encoder->estate=UTF8_1;
		    i++;
		}
		break;
	    case UTF8_3_1:
		if (buf[i]>=0x80 && buf[i]<=0xbf) {
		    encoder->char2=buf[i];
		    encoder->estate=UTF8_3_2;
		    i++;
		    continue;
		} else {
		    sgrep_error(sgrep,"UTF8 decoding error: 3,1 (%d<0x80 || >0xbf)\n",
				buf[i]);
		    ch=' ';
		    scanner->parse_errors++;
		    encoder->estate=UTF8_1;
		    i++;
		}
		break;
	    case UTF8_3_2:
		if (buf[i]>=0x80 && buf[i]<=0xbf) {
		    ch= ((encoder->char1&0x0f)<<12) |
			((encoder->char2&0x3f)<<6) | (buf[i]&0x3f);
		    encoder->estate=UTF8_1;
		    i++;
		    /* fprintf(sgrep->error_stream,"%x\n",ch); */
		} else {
		    sgrep_error(sgrep,"UTF8 decoding error: 3,2 (%d<0x80 || >0xbf)\n",
				buf[i]);
		    ch=' ';
		    scanner->parse_errors++;
		    encoder->estate=UTF8_1;
		    i++;
		}
		break;
	    case UTF16_BIG_START:
		if (buf[i]==0xff) {
		    encoder->estate=UTF16_BIG;
		    i++;
		    continue;
		} else {
		    sgrep_error(sgrep,"UTF16 decoding error Got 0xfe without 0xff\n");
		    ch=' ';
		    scanner->parse_errors++;
		    encoder->estate=UTF8_1;
		    i++;
		}
		break;
	    case UTF16_BIG:
		if (i+1>=len) {
		    sgrep_error(sgrep,"Odd number of bytes in UTF16-encoded file\n");
		    i++;
		    ch=-1;
		    continue;
		}
		ch=(buf[i]<<8)+buf[i+1];
		i+=2;
		/* sgrep_error(sgrep,"Char %d\n",ch); */
		break;
	    case UTF16_SMALL_START:
		if (buf[i]==0xfe) {
		    encoder->estate=UTF16_SMALL;
		    i++;
		    continue;
		} else {
		    sgrep_error(sgrep,"UTF16 decoding error Got 0xff without 0xfe\n");
		    ch=' ';
		    scanner->parse_errors++;
		    encoder->estate=UTF8_1;
		    i++;
		}
		break;
	    case UTF16_SMALL:
		if (i+1>=len) {
		    sgrep_error(sgrep,"Odd number of bytes in UTF16-encoded file\n");
		    i++;
		    ch=-1;
		    continue;
		}
		ch=(buf[i+1]<<8)+buf[i];
		i+=2;	
		break;
	    default:
		assert(0 && "Never here");
	    }
	}
	
	switch (state) {

	case SGML_PCDATA:
	    switch (ch) {
	    case '<':
		scanner->tags=encoder->prev;
		state=SGML_STAGO;
		NEXT_CH;
		break;
	    default:
		if (IN_CLIST(scanner->word_chars,ch)) {
		    state=SGML_WORD;
		    scanner->words=encoder->prev;
		    string_clear(scanner->word);
		    TERM_PUSH(scanner->word,'w');
		    TERM_PUSH(scanner->word,ch);
		} else if (ch=='&') {
		    scanner->entitys=encoder->prev;
		    push_state(scanner,SGML_PCDATA_ENTITY);
		    state=SGML_ENTITY_OPEN;
		}
		NEXT_CH;
	    }
	    break;	    

	case SGML_ENTITY_OPEN:
	    scanner->character_reference=0;
	    if (ch=='#') {
		state=SGML_CHARACTER_REFERENCE_OPEN;
		NEXT_CH;
	    } else if (IN_CLIST(scanner->name_start_chars,ch)) {
		string_clear(scanner->name);
		TERM_PUSH(scanner->name,'&');
		TERM_PUSH(scanner->name,ch);
		state=SGML_ENTITY;
		NEXT_CH;
	    } else {
		scanner->entitys=-1;
		state=pop_state(scanner);
	    }
	    break;

	case SGML_ENTITY:
	    if (IN_CLIST(scanner->name_chars,ch)) {
		TERM_PUSH(scanner->name,ch);
		NEXT_CH;
	    } else {
		if (ch==';') {
		    SGML_FOUND(scanner,POS);
		    NEXT_CH;
		} else {
		    SGML_FOUND(scanner,encoder->prev);
		}
		TERM_PUSH(scanner->name,';');
		state=pop_state(scanner);
	    }
	    break;
	    
	case SGML_CHARACTER_REFERENCE_OPEN:
	    if (ch=='x') {
		state=SGML_HEX_CHARACTER_REFERENCE;
		NEXT_CH;
	    } else if (ch>='0' && ch<='9') {
		scanner->character_reference=ch-'0';
		state=SGML_DECIMAL_CHARACTER_REFERENCE;
		NEXT_CH;
	    } else {
		scanner->entitys=-1;
		scanner->character_reference=0;
		scanner->parse_errors++;
		state=pop_state(scanner);
	    }
	    break;
	    
	case SGML_DECIMAL_CHARACTER_REFERENCE:
	    if (ch==';') {
		state=SGML_CHARACTER_REFERENCE_CLOSE;
		NEXT_CH;
		break;
	    } else if (ch>='0' && ch<='9') {
		scanner->character_reference=
		    scanner->character_reference*10+ch-'0';
		NEXT_CH;
	    } else {		
		state=SGML_CHARACTER_REFERENCE_CLOSE;
	    }	    
	    break;

	case SGML_HEX_CHARACTER_REFERENCE:
	    if (ch==';') {
		state=SGML_CHARACTER_REFERENCE_CLOSE;
		NEXT_CH;
	    } else if (ch>='0' && ch<='9') {
		scanner->character_reference=
		    scanner->character_reference*16+ch-'0';
		NEXT_CH;
	    } else  if (toupper(ch)>='A' && toupper(ch)<='F') {
		scanner->character_reference=scanner->character_reference*16+
		    toupper(ch)-'A'+10;
		NEXT_CH;
	    } else {
		state=SGML_CHARACTER_REFERENCE_CLOSE;
	    }
	    break;
		
	case SGML_CHARACTER_REFERENCE_CLOSE: {
	    char tmp[30];
	    sprintf(tmp,"&#x%x;",scanner->character_reference);
	    string_clear(scanner->name);
	    string_cat(scanner->name,tmp);
	    /* fprintf(stderr,"charref: %s\n",scanner->name); */
	    state=pop_state(scanner);
	    break;
	}

	case SGML_PCDATA_ENTITY:
	    if (scanner->character_reference>0 && 
		IN_CLIST(scanner->word_chars,scanner->character_reference)) {
		/* Entity was a character entity and was word character */
		scanner->words=scanner->entitys;
		string_clear(scanner->word);
		TERM_PUSH(scanner->word,'w');
		TERM_PUSH(scanner->word,scanner->character_reference);
		state=SGML_WORD;
	    } else if (scanner->entitys>=0 && 
		       IN_CLIST(scanner->word_chars,ch)) {
		/* Handles the case when word starts with some entity */
		scanner->words=scanner->entitys;
		string_clear(scanner->word);
		TERM_PUSH(scanner->word,'w');
		string_cat(scanner->word,string_to_char(scanner->name));
		state=SGML_WORD;
	    } else {
		state=SGML_PCDATA;
	    }
	    break;


	case SGML_WORD_ENTITY:
	    if (scanner->character_reference>0 && 
		IN_CLIST(scanner->word_chars,scanner->character_reference)) {
		/* Entity was a character entity and was word character */
		TERM_PUSH(scanner->word,scanner->character_reference);
		state=SGML_WORD;
	    } else {
		/* Handles the case when word continues with some entity */
		if (scanner->entitys>=0 && scanner->character_reference==0) {
		    /* Use the located entity only if it vas valid */
		    string_cat(scanner->word,string_to_char(scanner->name));
		    state=SGML_WORD;
		} else {
		    /* Entity ended the word: either in syntax error
		     * or non word char */
		    SGML_FOUND(scanner,scanner->word_end);
		    state=SGML_PCDATA;
		}
	    }
	    break;
	    
	case SGML_WORD:
	    if (IN_CLIST(scanner->word_chars,ch) && ch!='<') {
		TERM_PUSH(scanner->word,ch);
		NEXT_CH;
	    } else if (ch=='&') {
		scanner->word_end=encoder->prev;
		scanner->entitys=encoder->prev;
		push_state(scanner,SGML_WORD_ENTITY);
		state=SGML_ENTITY_OPEN;
		NEXT_CH;
	    } else {
		SGML_FOUND(scanner,encoder->prev);
		state=SGML_PCDATA;
	    }
	    break;

	case SGML_STAGO:
	    switch(ch) {
	    case '/':
		string_clear(scanner->gi);
		TERM_PUSH(scanner->gi,'e');
		state=SGML_END_TAG;
		NEXT_CH;
		break;
	    case '!':
		state=SGML_DECLARATION_START;
		NEXT_CH;
		break;
	    case '?':
		string_truncate(scanner->pi,1);
		state=SGML_PI;
		push_state(scanner,SGML_PCDATA);
		NEXT_CH;
		break;
	    default:
		if (IN_CLIST(scanner->name_start_chars,ch)) {
		    state=SGML_GI;
		    string_clear(scanner->gi);
		    TERM_PUSH(scanner->gi,'s');
		    TERM_PUSH(scanner->gi,ch);
		    NEXT_CH;
		} else {
		    state=SGML_PCDATA;
		}
		break;
	    }
	    break;

	case SGML_GI:
	    if (IN_CLIST(scanner->name_chars,ch)) {
		TERM_PUSH(scanner->gi,ch);
		NEXT_CH;
	    } else {
		state=SGML_W_ATTNAME;
	    }
	    break;

	case SGML_W_ATTNAME:
	    if (ch=='>') {
		state=SGML_STAGC;
	    } else if (IN_CLIST(scanner->name_start_chars,ch)) {
		string_truncate(scanner->aname,1);
		TERM_PUSH(scanner->aname,ch);
		scanner->anames=encoder->prev;
		state=SGML_ATTNAME;
		NEXT_CH;
	    } else {
		NEXT_CH;
	    }	    
	    break;

	case SGML_ATTNAME:
	    if (IN_CLIST(scanner->name_chars,ch)) {
		TERM_PUSH(scanner->aname,ch);
		NEXT_CH;
	    } else {
		state=SGML_W_ATTEQUAL;
	    }
	    break;

	case SGML_W_ATTEQUAL:
	    switch(ch) {
	    case ' ': case '\t':  case '\n':  case '\r': case '\v':
		NEXT_CH;
		break;
	    case '=':
		state=SGML_W_ATTVALUE;
		NEXT_CH;
		break;
		
	    default:
		if (ch=='>' || IN_CLIST(scanner->name_start_chars,ch)) {
		    /* FIXME: handle attribute value with no name */
		    /* fprintf(stderr,"Attribute with no value\n"); */
		}
		if (ch=='>') {
		    state=SGML_STAGC;
		} else if (IN_CLIST(scanner->name_start_chars,ch)) {
		    state=SGML_W_ATTNAME;
		} else {
		    /* Parse error (unexpected character) */
		    scanner->parse_errors++;
		    state=SGML_W_ATTNAME;
		}
		break;
	    }
	    break;

	case SGML_W_ATTVALUE:
	    switch(ch) {
	    case ' ': case '\t':  case '\n':  case '\r': case '\v':
		NEXT_CH;
		break;
	    case '>':
		/* Parse error.. */
		scanner->parse_errors++;
		state=SGML_STAGC;
		break;
	    case '\"':
		state=SGML_ATTVALUE_DQUOTED;
		scanner->avals=POS;
		string_truncate(scanner->aval,1);
		NEXT_CH;
		break;
	    case '\'':
		state=SGML_ATTVALUE_SQUOTED;
		scanner->avals=POS;
		string_truncate(scanner->aval,1);
		NEXT_CH;
		break;
	    default:
		if (IN_CLIST(scanner->name_chars,ch) || isgraph(ch)) {
		    state=SGML_ATTVALUE;
		    scanner->avals=encoder->prev;
		    string_truncate(scanner->aval,1);
		    string_push(scanner->aval,ch);
		    NEXT_CH;
		} else {
		    /* Parse error */
		    scanner->parse_errors++;
		    state=SGML_W_ATTNAME;
		    break;
		}
		break;
	    }
	    break;
	    
	case SGML_ATTVALUE:
	    if (ch=='>' || isspace(ch) ||
		!(IN_CLIST(scanner->name_chars,ch) || isgraph(ch))) {
		SGML_FOUND(scanner,encoder->prev);
		state=SGML_ATTRIBUTE_END;
		break;
	    }
	    TERM_PUSH(scanner->aval,ch);
	    NEXT_CH;
	    break;

	case SGML_ATTVALUE_DQUOTED:
	    if (ch!='\"') {
		TERM_PUSH(scanner->aval,ch);
		NEXT_CH;
		break;
	    }
	    SGML_FOUND(scanner,encoder->prev);
	    state=SGML_ATTRIBUTE_END;
	    NEXT_CH;
	    break;

	case SGML_ATTVALUE_SQUOTED:
	    if (ch!='\'') {
		TERM_PUSH(scanner->aval,ch);
		NEXT_CH;
		break;
	    }
	    SGML_FOUND(scanner,encoder->prev);
	    state=SGML_ATTRIBUTE_END;
	    NEXT_CH;
	    break;

	case SGML_ATTRIBUTE_END:
	    SGML_FOUND(scanner,encoder->prev);
	    state=SGML_W_ATTNAME;
	    break;   	    

	case SGML_STAGC:
	    SGML_FOUND(scanner,POS);
	    state=SGML_PCDATA;
	    NEXT_CH;
	    break;	    

	case SGML_END_TAG:
	    if (IN_CLIST(scanner->name_chars,ch)) {
		TERM_PUSH(scanner->gi,ch);
		NEXT_CH;
	    } else {
		state=SGML_W_ETAGC;
	    }
	    break;
	    
	case SGML_W_ETAGC:
	    if (ch=='>') {
		SGML_FOUND(scanner,POS);
		state=SGML_PCDATA;
	    }
	    NEXT_CH;
	    break;

	case SGML_DECLARATION_START:
	    switch(ch) {
	    case '-':
		scanner->comments=scanner->tags;
		state=SGML_COMMENT_START;
		push_state(scanner,SGML_PCDATA);
		NEXT_CH;
		break;
	    case '[':
		scanner->markeds=scanner->tags;
		state=SGML_MARKED_SECTION_START;
		string_clear(scanner->gi);
		TERM_PUSH(scanner->gi,'[');
		NEXT_CH;
		break;
	    default:
		if (ch=='D' || ch=='d') {
		    state=SGML_DOCTYPE_DECLARATION;
		    scanner->doctype_declarations=scanner->tags;
		    string_clear(scanner->name);
		    string_push(scanner->name,toupper(ch));
		    NEXT_CH;
		} else {
		    /* Parse error */
		    scanner->parse_errors++;
		    state=SGML_PCDATA;
		}
	    }
	    break;

	case SGML_COMMENT_START:
	    if (ch=='-') {
		state=SGML_COMMENT;
		NEXT_CH;
	    } else {
		scanner->parse_errors++;
		state=pop_state(scanner);
	    }
	    break;
	    
	case SGML_COMMENT:
	    if (ch=='-') {
		state=SGML_COMMENT_END1;
	    } else if (IN_CLIST(scanner->word_chars,ch)) {
		    state=SGML_COMMENT_WORD;
		    string_clear(scanner->comment_word);
		    TERM_PUSH(scanner->comment_word,'c');
		    TERM_PUSH(scanner->comment_word,ch);
		    scanner->comment_words=encoder->prev;
	    }
	    NEXT_CH;
	    break;

	case SGML_COMMENT_WORD:
	    /* FIXME: This does not accept - as word char inside comments */
	    if (IN_CLIST(scanner->word_chars,ch) && ch!='-') {
		TERM_PUSH(scanner->comment_word,ch);
		NEXT_CH;
	    } else {
		SGML_FOUND(scanner,encoder->prev);
		state=SGML_COMMENT;
	    }
	    break;

	case SGML_COMMENT_END1:
	    if (ch=='-') {
		state=SGML_COMMENT_END2;
		NEXT_CH;
	    } else {
		state=SGML_COMMENT;
	    }
	    break;

	    /* FIXME: generalize comment handling to situations
	     * like <!ATTLIST blah --sadfasdf-- blearhj --safsad--> */
	case SGML_COMMENT_END2:
	    if (ch=='>') {
		SGML_FOUND(scanner,POS);
		state=pop_state(scanner);
	    } else if (ch=='-') {
		state=SGML_COMMENT_START;
	    } else if (!isspace(ch)) {
		/* Since everything else except white space is
		 * a parse error */                 		   
		scanner->parse_errors++;
	    }
	    NEXT_CH;
	    break;

	case SGML_PI:
	    if (ch=='?' && scanner->type==XML_SCANNER) {
		state=SGML_PI_END;
	    } else if (ch=='>' && scanner->type!=XML_SCANNER) {
		SGML_FOUND(scanner,POS);
		state=pop_state(scanner);
	    } else {
		TERM_PUSH(scanner->pi,ch);
	    }
	    NEXT_CH;
	    break;

	case SGML_PI_END:
	    switch(ch) {
	    case '?':
		TERM_PUSH(scanner->pi,'?');
		break;
	    case '>':
		SGML_FOUND(scanner,POS);
		state=pop_state(scanner);
		break;
	    default:
		TERM_PUSH(scanner->pi,'?');
		TERM_PUSH(scanner->pi,ch);
		state=SGML_PI;
	    }
	    NEXT_CH;
	    break;

	case SGML_MARKED_SECTION_START:
	    /* Using gi also for marked section names. */
	    /* NOTE: entity references in marked section type are allowed
	     * to enable the SGML IGNORE and PCDATA entity tricks */
	    /* FIXME: this probably won't work (maybe not a big deal) */
	    if ( (string_len(scanner->gi)==1 &&
		  (IN_CLIST(scanner->name_start_chars,ch) || ch=='&' || ch==';')) ||
		 (string_len(scanner->gi)>1 &&
		  (IN_CLIST(scanner->name_chars,ch) || ch=='&' || ch==';')) ) {
		TERM_PUSH(scanner->gi,ch);
		NEXT_CH;
	    } else {
		state=SGML_MARKED_SECTION_START2;
	    }
	    break;

	case SGML_MARKED_SECTION_START2:
	    if (isspace(ch)) {
		NEXT_CH;
	    } else if (ch=='['){
		if (strcmp(string_to_char(scanner->gi),"[CDATA")==0) {
		    state=SGML_CDATA_MARKED_SECTION;
		} else {
		    /* Since extracting other than CDATA marked sections
		     * would need a stack this only reports the start of
		     * those sections. Maybe in version 3..*/
		    SGML_FOUND(scanner,POS);
		    state=SGML_PCDATA;
		}
		NEXT_CH;
	    } else {
		/* Parse error */
		scanner->parse_errors++;
		state=SGML_PCDATA;
	    }
	    break;
	    
	case SGML_CDATA_MARKED_SECTION:
	    if (ch==']') {
		state=SGML_CDATA_MARKED_SECTION_END1;
	    } else if (IN_CLIST(scanner->word_chars,ch)) {
		string_clear(scanner->word);
		TERM_PUSH(scanner->word,'w');
		TERM_PUSH(scanner->word,ch);
		scanner->words=encoder->prev;
		state=SGML_CDATA_MARKED_SECTION_WORD;
	    }
	    NEXT_CH;
	    break;

	case SGML_CDATA_MARKED_SECTION_WORD:
	    if (IN_CLIST(scanner->word_chars,ch) && ch!=']') {
		TERM_PUSH(scanner->word,ch);
		NEXT_CH;
	    } else {
		SGML_FOUND(scanner,encoder->prev);
		state=SGML_CDATA_MARKED_SECTION;
	    }
	    break;

	case SGML_CDATA_MARKED_SECTION_END1:
	    if (ch==']') {
		state=SGML_CDATA_MARKED_SECTION_END2;
		NEXT_CH;
	    } else {
		state=SGML_CDATA_MARKED_SECTION;
	    }
	    break;

	case SGML_CDATA_MARKED_SECTION_END2:
	    if (ch=='>') {
		SGML_FOUND(scanner,POS);
		NEXT_CH;
		state=SGML_PCDATA;
	    } else if (ch==']') {
		NEXT_CH;
	    } else {
		state=SGML_CDATA_MARKED_SECTION;
	    }
	    break;

	case SGML_DOCTYPE_DECLARATION: 
	    if (string_len(scanner->name)<7 
		&& toupper(ch)==("DOCTYPE")[string_len(scanner->name)]) {
	        TERM_PUSH(scanner->name,toupper(ch));
		NEXT_CH;
	    } else if (string_len(scanner->name)==7 && isspace(ch)) {
		string_clear(scanner->name);
		TERM_PUSH(scanner->name,'d');
		TERM_PUSH(scanner->name,'n');
		state=SGML_DOCTYPE;
		NEXT_CH;
	    } else {
		scanner->parse_errors++;
		state=SGML_PCDATA;
	    }
	    break;

	case SGML_DOCTYPE:
	    if (string_len(scanner->name)==2) {
		if (IN_CLIST(scanner->name_start_chars,ch)) {
		    TERM_PUSH(scanner->name,ch);
		    scanner->doctypes=encoder->prev;
		    NEXT_CH;
		} else if (!isspace(ch)) {
		    scanner->parse_errors++;
		    state=SGML_PCDATA;
		} else {
		    NEXT_CH;
		}
	    } else {
		if (IN_CLIST(scanner->name_chars,ch)) {
		    TERM_PUSH(scanner->name,ch);
		    NEXT_CH;
		} else {
		    SGML_FOUND(scanner,encoder->prev);
		    state=SGML_DOCTYPE_EXTERNAL;
		}
	    }
	    break;

	case SGML_DOCTYPE_EXTERNAL:
	    switch(ch) {
	    case '[':
		state=SGML_DOCTYPE_INTERNAL;
		NEXT_CH;
		break;
	    case 'P': case 'p':
		/* _P_ublic */
		scanner->publici=1;
		state=SGML_DOCTYPE_PUBLIC;
		NEXT_CH;
		break;
	    case 'S': case 's':
		scanner->systemi=1;
		state=SGML_DOCTYPE_SYSTEM;
		NEXT_CH;
		break;
	    case '>':
		state=SGML_DOCTYPE_END;
		break;
	    default:
		if (!isspace(ch)) {
		    scanner->parse_errors++;
		    state=SGML_PCDATA;
		}
		NEXT_CH;
	    }
	    break;
		
	case SGML_DOCTYPE_PUBLIC:
	    if (("PUBLIC")[scanner->publici]==toupper(ch)) {
		scanner->publici++;
		if (scanner->publici==6) {
		    state=SGML_DOCTYPE_PUBLIC_ID_START;
		}
		NEXT_CH;
	    } else {
		scanner->parse_errors++;
		state=SGML_PCDATA;
	    }
	    break;

	case SGML_DOCTYPE_SYSTEM:
	    if (("SYSTEM")[scanner->systemi]==toupper(ch)) {
		scanner->systemi++;
		if (scanner->systemi==6) {
		    state=SGML_DOCTYPE_SYSTEM_ID_START;
		}
		NEXT_CH;
	    } else {
		scanner->parse_errors++;
		state=SGML_PCDATA;
	    }
	    break;

	case SGML_DOCTYPE_PUBLIC_ID_START:
	    if (ch=='"' || ch=='\'') {
		state=SGML_LITERAL_START;
		push_state(scanner,SGML_DOCTYPE_PUBLIC_ID);
	    } else if (isspace(ch)) {
		NEXT_CH;
	    } else {
		scanner->parse_errors++;
		state=SGML_PCDATA;	
	    }
	    break;

	case SGML_WAITING_LITERAL:
	    if (isspace(ch)) {
		NEXT_CH;
	    } else {
		if (ch=='"' || ch=='\'') {
		    state=SGML_LITERAL_START;
		} else {
		    scanner->parse_errors++;
		    scanner->literals=-1;
		    state=pop_state(scanner);
		}
	    }
	    break;

	case SGML_LITERAL_START:
	    scanner->literals=start+i;
	    string_truncate(scanner->literal,3);
	    state=(ch=='"') ? SGML_LITERAL_DQUOTED : SGML_LITERAL_SQUOTED;
	    NEXT_CH;
	    break;

	case SGML_LITERAL_DQUOTED:
	    if (ch!='"') {
		TERM_PUSH(scanner->literal,ch);
		NEXT_CH;
	    } else {
		state=pop_state(scanner);
	    }
	    break;

	case SGML_LITERAL_SQUOTED:
	    if (ch!='\'') {
		TERM_PUSH(scanner->literal,ch);
		NEXT_CH;
	    } else {
		state=pop_state(scanner);
	    }
	    break;
	    
	case SGML_DOCTYPE_PUBLIC_ID:
	    SGML_FOUND(scanner,encoder->prev);
	    state=SGML_DOCTYPE_SYSTEM_ID_START;
	    NEXT_CH;
	    break;

	case SGML_DOCTYPE_SYSTEM_ID_START:
	    if (ch=='[') {
		state=SGML_DOCTYPE_INTERNAL;
	    } else if (ch=='"' || ch=='\'') {
		state=SGML_LITERAL_START;
		push_state(scanner,SGML_DOCTYPE_SYSTEM_ID);
	    } else if (isspace(ch)) {
		NEXT_CH;
	    } else {
		scanner->parse_errors++;
		state=SGML_PCDATA;	
	    }
	    break;

	case SGML_DOCTYPE_SYSTEM_ID:
	    SGML_FOUND(scanner,encoder->prev);
	    state=SGML_DOCTYPE_INTERNAL_START;
	    NEXT_CH;
	    break;
	    
	case SGML_DOCTYPE_INTERNAL_START:
	    switch(ch) {
	    case '[':
		state=SGML_DOCTYPE_INTERNAL;
		NEXT_CH;
		break;
	    case '>':
		state=SGML_DOCTYPE_END;
		break;
	    default:
		if (isspace(ch)) {
		    NEXT_CH;
		} else {
		    scanner->parse_errors++;
		    state=SGML_PCDATA;
		}
		break;
	    }
	    break;		    

	case SGML_DOCTYPE_INTERNAL:
	    switch(ch) {
	    case '<':
		scanner->internal_declarations=encoder->prev;
		state=SGML_INTERNAL_DECLARATION_START1;
		break;
	    case '%':
		/* sgrep_error(sgrep,"PER\n"); */
		scanner->entitys=encoder->prev;
		state=SGML_PEREFERENCE;
		NEXT_CH;
		break;
	    case ']':
		state=SGML_DOCTYPE_END;
		break;
	    default:
		if (!isspace(ch)) {
		scanner->parse_errors++;
		}
		break;
	    }
	    NEXT_CH;
	    break;

	case SGML_PEREFERENCE:
	    if (IN_CLIST(scanner->name_chars,ch)) {
		/* Nothing */
	    } else if (ch==';') {
		state=SGML_DOCTYPE_INTERNAL;
	    } else if (isspace(ch)) {
		state=SGML_DOCTYPE_INTERNAL;
	    } else {
		scanner->parse_errors++;
		state=SGML_DOCTYPE_INTERNAL;
	    }
	    NEXT_CH;
	    break;
		
	case SGML_INTERNAL_DECLARATION_START1:
	    switch (ch) {
	    case '!':
		state=SGML_INTERNAL_DECLARATION_START2;
		NEXT_CH;
		break;
	    case '?':
		scanner->tags=scanner->internal_declarations;
		string_truncate(scanner->pi,1);
		state=SGML_PI;
		push_state(scanner,SGML_DOCTYPE_INTERNAL);
		NEXT_CH;
		break;
	    default:
		scanner->parse_errors++;
		state=SGML_DOCTYPE_INTERNAL;
		break;
	    }
	    break;
	    
	case SGML_INTERNAL_DECLARATION_START2:
	    if (ch=='-') {
		scanner->comments=scanner->internal_declarations;
		push_state(scanner,SGML_DOCTYPE_INTERNAL);
		state=SGML_COMMENT_START;
		NEXT_CH;
	    } else if (isalpha(ch)) {
  		state=SGML_INTERNAL_DECLARATION_NAME;
		string_clear(scanner->name);
		TERM_PUSH(scanner->name,toupper(ch));
		NEXT_CH;
	    } else {
		scanner->parse_errors++;
		state=SGML_DOCTYPE_INTERNAL;
	    }
	    break;
		
	case SGML_INTERNAL_DECLARATION_NAME: 
	    if (isalpha(ch) &&
		string_len(scanner->name)<10) {
		TERM_PUSH(scanner->name,ch);
		NEXT_CH;
	    } else if (isspace(ch)) {
		const char *name;
		string_toupper(scanner->name,0);
		name=string_to_char(scanner->name);
		if (strcmp(name,"ENTITY")==0) {
		    scanner->entity_has_systemid=0;
		    scanner->entity_is_ndata=0;
		    state=SGML_ENTITY_DECLARATION;
		} else if (strcmp(name,"ELEMENT")==0) {
		    state=SGML_ELEMENT_TYPE_DECLARATION;
		} else if (strcmp(name,"NOTATION")==0) {
		    state=SGML_NOTATION_DECLARATION;
		} else if (strcmp(name,"ATTLIST")==0) {
		    state=SGML_ATTLIST_DECLARATION;
		} else {
		    scanner->parse_errors++;
		    state=SGML_DOCTYPE_INTERNAL;
		}
		NEXT_CH;
	    } else {
		scanner->parse_errors++;
		state=SGML_DOCTYPE_INTERNAL;
	    }
	    break;

	case SGML_ENTITY_DECLARATION:
	    if (ch=='%') {
		/* Parameter entities are handled just like any other
		 * entities */
		NEXT_CH;
	    } else if (IN_CLIST(scanner->name_start_chars,ch)) {
		state=SGML_ENTITY_DECLARATION_NAME;
		string_clear(scanner->name);
		string_cat(scanner->name,"!ed");
		string_push(scanner->name,ch);
		NEXT_CH;
	    } else if (isspace(ch)) {
		NEXT_CH;
	    } else {
		scanner->parse_errors++;
		state=SGML_DOCTYPE_INTERNAL;
	    }
	    break;

	case SGML_ENTITY_DECLARATION_NAME:
	    if (IN_CLIST(scanner->name_chars,ch)) {
		TERM_PUSH(scanner->name,ch);
		NEXT_CH;
	    } else {
		state=SGML_ENTITY_DEFINITION;
	    }
	    break;
	    
	case SGML_ENTITY_DEFINITION:
	    if (ch=='"') {
		state=SGML_GENERAL_ENTITY_DEFINITION_DQUOTED;
		scanner->literals=POS;
		NEXT_CH;
	    } else if (ch=='\'') {
		state=SGML_GENERAL_ENTITY_DEFINITION_SQUOTED;
		scanner->literals=POS;
		NEXT_CH;
	    } else if (isspace(ch)) {
		NEXT_CH;
	    } else if (isalpha(ch)) {
		push_state(scanner,SGML_ENTITY_DEFINITION_TYPE);
		string_clear(scanner->name2);
		state=SGML_RESERVED_WORD;
	    } else {
		scanner->parse_errors++;
		state=SGML_DOCTYPE_INTERNAL;
	    }
	    break;

	case SGML_RESERVED_WORD:
	    if (isalpha(ch)) {
		TERM_PUSH(scanner->name2,toupper(ch));
		NEXT_CH;
	    } else {
		state=pop_state(scanner);
	    }
	    break;

	case SGML_ENTITY_DEFINITION_TYPE:
	    if (strcmp(string_to_char(scanner->name2),"SYSTEM")==0) {
		push_state(scanner,SGML_ENTITY_DEFINITION_SYSTEM_ID);
		state=SGML_WAITING_LITERAL;
	    } else if (strcmp(string_to_char(scanner->name2),"PUBLIC")==0) {
		push_state(scanner,SGML_ENTITY_DEFINITION_PUBLIC_ID);
		state=SGML_WAITING_LITERAL;
	    } else if (strcmp(string_to_char(scanner->name2),"CDATA")==0 ||
		       strcmp(string_to_char(scanner->name2),"SDATA")==0) {
		state=SGML_LITERAL_ENTITY;
	    } else {
		scanner->parse_errors++;
		state=SGML_DOCTYPE_INTERNAL;
	    }
	    break;
		    
	case SGML_LITERAL_ENTITY:
	    if (ch=='"') {
		state=SGML_GENERAL_ENTITY_DEFINITION_DQUOTED;
		scanner->literals=POS;
		NEXT_CH;
	    } else if (ch=='\'') {
		state=SGML_GENERAL_ENTITY_DEFINITION_SQUOTED;
		scanner->literals=POS;
		NEXT_CH;
	    } else if (isspace(ch)) {
		NEXT_CH;
	    } else {
		scanner->parse_errors++;
	    }
	    break;
		
		
	case SGML_GENERAL_ENTITY_DEFINITION_DQUOTED:
	    if (ch=='"') {
		SGML_FOUND(scanner,encoder->prev);
		state=SGML_ENTITY_DEFINITION_END;
	    }
	    NEXT_CH;
	    break;
		    
	case SGML_GENERAL_ENTITY_DEFINITION_SQUOTED:
	    if (ch=='\'') {	
		SGML_FOUND(scanner,encoder->prev);
		state=SGML_ENTITY_DEFINITION_END;
	    }
	    NEXT_CH;
	    break;
	
	case SGML_ENTITY_DEFINITION_END:
	    if (ch=='>') {
		SGML_FOUND(scanner,POS);
		state=SGML_DOCTYPE_INTERNAL;
		NEXT_CH;
		break;
	    } else if (isspace(ch)) {
		NEXT_CH;
	    } else {
		scanner->parse_errors++;
		state=SGML_DOCTYPE_INTERNAL;
	    }
	    break;
	    
	case SGML_ENTITY_DEFINITION_PUBLIC_ID:
	    if (scanner->literals>0) {
		SGML_FOUND(scanner,encoder->prev);
		state=SGML_WAITING_ENTITY_DEFINITION_SYSTEM_ID;
		NEXT_CH;
	    } else {
		state=SGML_DOCTYPE_INTERNAL;
	    }
	    break;
	    
	case SGML_WAITING_ENTITY_DEFINITION_SYSTEM_ID:
	    switch(ch) {
	    case '"':
	    case '\'':
	        push_state(scanner,SGML_ENTITY_DEFINITION_SYSTEM_ID);
		state=SGML_LITERAL_START;
		break;
	    default:
		if (isspace(ch)) {
		    NEXT_CH;
		} else {
		    state=SGML_ENTITY_DEFINITION_NDATA;
		}
	    }
	    break;
	    
	case SGML_ENTITY_DEFINITION_SYSTEM_ID:
	    if (scanner->literals>0) {
		SGML_FOUND(scanner,encoder->prev);
		scanner->entity_has_systemid=1;
		state=SGML_ENTITY_DEFINITION_NDATA;
		NEXT_CH;
	    }
	    break;
	    
	case SGML_ENTITY_DEFINITION_NDATA:
	    if (ch=='>') {
		state=SGML_ENTITY_DEFINITION_END;
	    } else if (isalpha(ch)) {
		string_clear(scanner->name2);
		push_state(scanner,SGML_ENTITY_DEFINITION_NDATA2);
		state=SGML_RESERVED_WORD;
	    } else if (isspace(ch)) {
		NEXT_CH;
	    } else {
		scanner->parse_errors++;
		state=SGML_DOCTYPE_INTERNAL;
	    }
	    break;

	case SGML_ENTITY_DEFINITION_NDATA2:
	    if (strcmp(string_to_char(scanner->name2),"NDATA")==0) {
		scanner->entity_is_ndata=1;
		if (isspace(ch)) {
		    NEXT_CH;
		} else if (IN_CLIST(scanner->name_start_chars,ch)){
		    string_clear(scanner->name2);
		    string_cat(scanner->name2,"!en");
		    scanner->name2s=encoder->prev;
		    state=SGML_ENTITY_DEFINITION_NDATA_NAME;
		} else {
		    scanner->parse_errors++;
		    state=SGML_DOCTYPE_INTERNAL;
		}
	    } else {
		scanner->parse_errors++;
		state=SGML_DOCTYPE_INTERNAL;
	    }
	    break;

	case SGML_ENTITY_DEFINITION_NDATA_NAME:
	    if (IN_CLIST(scanner->name_chars,ch)) {
		TERM_PUSH(scanner->name2,ch);
		NEXT_CH;
	    } else {
		SGML_FOUND(scanner,encoder->prev);		
		state=SGML_ENTITY_DEFINITION_END;
	    }
	    break;

	    /* FIXME: could be useful */
	case SGML_ELEMENT_TYPE_DECLARATION:
	    if (ch=='>') {
		SGML_FOUND(scanner,POS);
		state=SGML_DOCTYPE_INTERNAL;
	    }
	    NEXT_CH;
	    break;

	    /* FIXME: could be useful */
	case SGML_ATTLIST_DECLARATION:
	    if (ch=='>') {
		SGML_FOUND(scanner,POS);
		state=SGML_DOCTYPE_INTERNAL;
	    }
	    NEXT_CH;
	    break;
	    
	    /* FIXME: could be useful */
	case SGML_NOTATION_DECLARATION:
	    if (ch=='>') {
		SGML_FOUND(scanner,POS);
		state=SGML_DOCTYPE_INTERNAL;
	    }
	    NEXT_CH;
	    break;
	

	case SGML_DOCTYPE_END:
	    if (ch=='>') {
		SGML_FOUND(scanner,POS);
		state=SGML_PCDATA;
		NEXT_CH;
	    } else if (isspace(ch)) {
		NEXT_CH;
	    } else {
		scanner->parse_errors++;
		state=SGML_PCDATA;
	    }
	    break;

	default:
	    sgrep_error(scanner->sgrep,
			"SGML-scanner in unimplemented state. Switching to PCDATA\n");
	    state=SGML_PCDATA;
	    break;
	}
	

    }
    scanner->state=state;
    return SGREP_OK;
#undef NEXT_CH
}
