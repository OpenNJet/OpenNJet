%{
#include <stdio.h>
#include "njt_stream_sniffer.h"
#include "njt_stream_sniffer_parse.h"
void sniffererror(sniffer_exp_parse_node_t **tree_root, const char *msg);
void njt_sniffer_reset();
int sniffer_paren_count = 0; 
int inside_sniffer_paren_count = 0; // count for () within $http  =   [^ab]c.()()$$$
char sniffer_parsed_buf[4096]; // temp value for [^ab]c.()()$$$
char* string_sniffer_buf_ptr; 
int sniffer_closed = 0;
int sniffer_idx = 0;
%}
%x in_sniffer_str
%option noyywrap
%%



\( {
    if (sniffer_paren_count == 0) { printf("Outermost Opening Parenthesis\n"); sniffer_closed = 0; sniffer_idx=0; BEGIN(INITIAL); }
    ++sniffer_paren_count; printf("Parenthese count is %d\n", sniffer_paren_count);
    return '(';
};
\) {
    printf("closed = %d\n", sniffer_closed);
    if (sniffer_closed == 1) { printf("error"); sniffererror(NULL, "already sniffer_closed"); return ERROR; }
    if (sniffer_paren_count == 0) {
        printf("finished \n");
        sniffer_closed = 1;
    } else {
        --sniffer_paren_count;
        printf("Parenthese count is %d\n", sniffer_paren_count);
        if (sniffer_paren_count == 0) { 
            printf("Outermost Closing Parenthesis\n"); 
            yyless(0);
        }
        return ')';
    }
    printf("sniffer_closed = %d\n", sniffer_closed);
};

\|\| { printf("OR \n"); return OR; };
&&   { printf("AND \n"); return AND; };

[(0x)][a-zA-Z][_0-9a-zA-Z]* { 
    printf("IN_STR \n"); BEGIN(in_sniffer_str);
    string_sniffer_buf_ptr = sniffer_parsed_buf;
    char *yptr = yytext; while ( *yptr ) { *string_sniffer_buf_ptr++ = *yptr++; };
};
<in_sniffer_str>\( {
    inside_sniffer_paren_count++ ;
    *string_sniffer_buf_ptr++ ='(';
    printf("inside_sniffer_paren_count: %d\n", inside_sniffer_paren_count);
};
<in_sniffer_str>\) { /* assume () in in_sniffer_str must match each other */
    if (inside_sniffer_paren_count == 0) {
        BEGIN(INITIAL);
        *string_sniffer_buf_ptr ='\0';
        printf("loc_exp: %s \n", sniffer_parsed_buf);
        snifferlval.loc_exp = new_sniffer_exp(strdup(sniffer_parsed_buf), sniffer_idx++);
        inside_sniffer_paren_count = 0;
        yyless(0); // reparse the ')', from the INITIAL start condition
        return LOC_EXP;
    } else {
         inside_sniffer_paren_count--;
         *string_sniffer_buf_ptr++ =')';
         printf("inside_sniffer_paren_count: %d\n", inside_sniffer_paren_count);
    }
};
<in_sniffer_str>(\&\&|\|\|) { /* left part of bool op finished */
    if (inside_sniffer_paren_count == 0) {
        *string_sniffer_buf_ptr ='\0';
        printf("loc_exp: %s \n", sniffer_parsed_buf);
        BEGIN(INITIAL);
        snifferlval.loc_exp = new_sniffer_exp(strdup(sniffer_parsed_buf), sniffer_idx++);
        yyless(0);
        return LOC_EXP;
    } else {
        printf("inside_sniffer_paren_count: %d\n", inside_sniffer_paren_count);
        printf("loc_exp: %s \n", sniffer_parsed_buf);
        sniffererror(NULL, "mismatch parenthese in exp");
        return ERROR;
    }
};

<in_sniffer_str>\| { *string_sniffer_buf_ptr++ ='|'; };
<in_sniffer_str>& { *string_sniffer_buf_ptr++ ='&'; };
<in_sniffer_str>\\ { *string_sniffer_buf_ptr++ ='\\'; };
<in_sniffer_str>\\n { *string_sniffer_buf_ptr++ ='\n'; };
<in_sniffer_str>\\t { *string_sniffer_buf_ptr++ ='\t'; };
<in_sniffer_str>\" { *string_sniffer_buf_ptr++ ='"'; };
<in_sniffer_str>\\\" { *string_sniffer_buf_ptr++ ='"'; };

 <in_sniffer_str>[^\(\)&|\\\n\t\"]+  {
    char *yptr = yytext;
    while ( *yptr ) {*string_sniffer_buf_ptr++ = *yptr++;};
 };

\\\n    printf("c> "); /* ignore line continuation */
[ \t\n]   /* ignore white space or newline */
<*>.   { printf("LAST rule \n"); sniffererror(NULL, yytext); return ERROR; };

%%


void sniffererror(sniffer_exp_parse_node_t **tree_root, const char *msg) {
    njt_sniffer_reset();
    printf("Syntax error: %s\n", msg);
}; 

void njt_sniffer_reset() {
    sniffer_paren_count = 0; 
    inside_sniffer_paren_count = 0; // count for () within $http  =   [^ab]c.()()$$$
    sniffer_closed = 0;
    sniffer_idx = 0;
}

sniffer_exp_t* 
new_sniffer_exp(char *exp, int idx)
{
    sniffer_exp_t* loc_exp = malloc(sizeof(sniffer_exp_t));
    if (!loc_exp) {
        exit(0);
    }
    loc_exp->exp = exp;
    loc_exp->idx = idx;
    return loc_exp;
}

