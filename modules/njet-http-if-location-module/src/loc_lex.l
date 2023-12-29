%{
#include <stdio.h>
#include "njt_http_if_location_api.h"
#include "njt_http_if_location_parse.h"
// void yyerror(char *s, ...);
void yyerror(loc_parse_node_t **tree_root, const char *msg);
int paren_count = 0; 
int inside_paren_count = 0; // count for () within $http  =   [^ab]c.()()$$$
char _parsed_buf[4096]; // temp value for [^ab]c.()()$$$
char* string_buf_ptr; 
int closed = 0;
int idx = 0;
%}

%x in_str

%option noyywrap


%%



\( {
    if (paren_count == 0) { printf("Outermost Opening Parenthesis\n"); closed = 0; idx=0; BEGIN(INITIAL); }
    ++paren_count; printf("Parenthese count is %d\n", paren_count);
    return '(';
};
\) {
    printf("closed = %d\n", closed);
    if (closed == 1) { printf("error"); yyerror(NULL, "already closed"); return ERROR; }
    if (paren_count == 0) {
        printf("finished \n");
        closed = 1;
    } else {
        --paren_count;
        printf("Parenthese count is %d\n", paren_count);
        if (paren_count == 0) { 
            printf("Outermost Closing Parenthesis\n"); 
            yyless(0);
        }
        return ')';
    }
    printf("closed = %d\n", closed);
};

\|\| { printf("OR \n"); return OR; };
&&   { printf("AND \n"); return AND; };

[$][a-zA-Z][_0-9a-zA-Z]* { 
    printf("IN_STR \n"); BEGIN(in_str);
    string_buf_ptr = _parsed_buf;
    char *yptr = yytext; while ( *yptr ) { *string_buf_ptr++ = *yptr++; };
};
<in_str>\( {
    inside_paren_count++ ;
    *string_buf_ptr++ ='(';
    printf("inside_paren_count: %d\n", inside_paren_count);
};
<in_str>\) { /* assume () in in_str must match each other */
    if (inside_paren_count == 0) {
        BEGIN(INITIAL);
        *string_buf_ptr ='\0';
        printf("loc_exp: %s \n", _parsed_buf);
        yylval.loc_exp = new_loc_exp(strdup(_parsed_buf), idx++);
        inside_paren_count = 0;
        yyless(0); // reparse the ')', from the INITIAL start condition
        return LOC_EXP;
    } else {
         inside_paren_count--;
         *string_buf_ptr++ =')';
         printf("inside_paren_count: %d\n", inside_paren_count);
    }
};
<in_str>(\&\&|\|\|) { /* left part of bool op finished */
    if (inside_paren_count == 0) {
        *string_buf_ptr ='\0';
        printf("loc_exp: %s \n", _parsed_buf);
        BEGIN(INITIAL);
        yylval.loc_exp = new_loc_exp(strdup(_parsed_buf), idx++);
        yyless(0);
        return LOC_EXP;
    } else {
        printf("inside_paren_count: %d\n", inside_paren_count);
        printf("loc_exp: %s \n", _parsed_buf);
        yyerror(NULL, "mismatch parenthese in exp");
        return ERROR;
    }
};

<in_str>\| { *string_buf_ptr++ ='|'; };
<in_str>& { *string_buf_ptr++ ='&'; };
<in_str>\\ { *string_buf_ptr++ ='\\'; };
<in_str>\\n { *string_buf_ptr++ ='\n'; };
<in_str>\\t { *string_buf_ptr++ ='\t'; };
<in_str>\" { *string_buf_ptr++ ='"'; };
<in_str>\\\" { *string_buf_ptr++ ='"'; };

 <in_str>[^\(\)&|\\\n\t\"]+  {
    char *yptr = yytext;
    while ( *yptr ) {*string_buf_ptr++ = *yptr++;};
 };

\\\n    printf("c> "); /* ignore line continuation */
[ \t\n]   /* ignore white space or newline */
<*>.   { printf("LAST rule \n"); yyerror(NULL, yytext); return ERROR; };

%%

/*
<in_str>\\\( { *string_buf_ptr++ ='('; };
<in_str>\\\) { *string_buf_ptr++ =')'; };
 <in_str>[^ ^\t=~\(\)\n&|][^\(\)\n&|]* {
/* str should not start with ~| |\t|^|(|) *//* 
    ECHO;
    printf("\n");
}
<in_str>\\t    { 
    printf("esc-t \n"); *string_buf_ptr++ ='\t';
};
<in_str>\\r    { 
    printf("CR \n"); *string_buf_ptr++ ='\r';
};
<in_str>\\n    {
    printf("newline \n"); *string_buf_ptr++ ='\n';
};
<in_str>[ ]   {
    printf("space \n");
    *string_buf_ptr++ =' ';
};
*/

/* int main() {
// [.]+       { yyerror("Mystery character %c\n", *yytext); };
       yylex();
       return 0;
}; */

void yyerror(loc_parse_node_t **tree_root, const char *msg) {
    reset();
    printf("Syntax error: %s\n", msg);
}; 

void reset() {
    paren_count = 0; 
    inside_paren_count = 0; // count for () within $http  =   [^ab]c.()()$$$
    closed = 0;
    idx = 0;
}

