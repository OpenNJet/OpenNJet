/* calculator with AST */

%{
#  include <stdio.h>
#  include <stdlib.h>
#  include "loc_eval.h"
int yylex();
int yyerror(char const * s);

int loc_exp_dyn_eval_result;
loc_parse_node_t *loc_exp_dyn_parse_tree;
%}

%union {
  loc_parse_node_t *node;
  loc_exp_t *loc_exp;
}


/* declare tokens */
%token <loc_exp> LOC_EXP
%token EOL
%token OR AND
%token ERROR


%left OR
%left AND

%type <node> eval_tree exp
%start eval_tree

%destructor {free_tree($$);} <node>;


%%
exp:  LOC_EXP {  printf("BISON: LOC_EXP\n"); $$ = new_loc_parse_exp_node($1); }
   | '(' exp ')'          { printf("BISON: (EXP) \n"); $$ = $2; }
   | exp OR  exp          { printf("BISON: OR \n"); $$ = new_loc_parse_op_node(BOOL_OP_OR, $1,$3); }
   | exp AND exp          { printf("BISON: AND \n");$$ = new_loc_parse_op_node(BOOL_OP_AND, $1,$3);}
;

eval_tree: /* nothing */
  | eval_tree exp EOL {
    dump_tree($2, 0);
    loc_exp_dyn_eval_result = eval_loc_parse_tree($2);
    loc_exp_dyn_parse_tree = $2;
    printf("= %d\n> ", loc_exp_dyn_eval_result);
    // free_tree($2);
    // free($2);
    return 0;
    }
  | eval_tree error EOL { yyerrok; printf("> "); }
  | eval_tree ERROR { YYABORT; }
 ;

%%
