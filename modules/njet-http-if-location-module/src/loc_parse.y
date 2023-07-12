%{
#  include <stdio.h>
#  include <stdlib.h>
#  include "njt_http_if_location_api.h"
int yylex();
void yyerror(loc_parse_node_t **tree_root,  const char * s);

int loc_exp_dyn_eval_result;
loc_parse_node_t *loc_exp_dyn_parse_tree;
%}

%union {
  loc_parse_node_t *node;
  loc_exp_t *loc_exp;
}



%parse-param { loc_parse_node_t **tree_root }
/* declare tokens */
%token <loc_exp> LOC_EXP
/* %oken EOL */
%token OR AND
%token ERROR


%left OR
%left AND

%type <node> eval_tree exp
%start eval_tree

/* %destructor { printf ("Discarding tagless symbol.\n"); } <> */
/* %destructor { free ($$); } <*> */
/* %destructor {free_tree($$);} <node> */
%destructor {  printf ("Discarding symbol: OR at line %d\n", @$.first_line); } OR
%destructor {  printf ("Discarding symbol: AND at line %d\n", @$.first_line); } AND
/* %destructor {  printf ("Discarding symbol: EOL at line %d\n", @$.first_line); } EOL */
%destructor {  printf ("Discarding symbol: ERROR at line %d\n", @$.first_line); } ERROR 
%destructor { if($$) { free_tree ($$); printf ("Discarding symbol: exp at line %d\n", @$.first_line); free($$);} } exp
%destructor { if($$) { free_tree ($$); printf ("Discarding symbol: eval_tree at line %d\n", @$.first_line); free($$);} } eval_tree


%%

exp:   {printf("BISON NULL_EXP: \n"); $$=NULL; YYABORT;}
   | LOC_EXP {  printf("BISON: LOC_EXP\n"); $$ = new_loc_parse_exp_node($1); }
   | '(' exp ')'          { printf("BISON: (EXP) \n"); $$ = $2; }
   | exp OR  exp          { printf("BISON: OR \n"); $$ = new_loc_parse_op_node(BOOL_OP_OR, $1,$3); }
   | exp AND exp          { printf("BISON: AND \n");$$ = new_loc_parse_op_node(BOOL_OP_AND, $1,$3);}

eval_tree: {$$ = NULL; }/* nothing */
  | eval_tree exp YYEOF {
    dump_tree($2, 0);
    // loc_exp_dyn_eval_result = eval_loc_parse_tree($2);
    loc_exp_dyn_parse_tree = $2;
    *tree_root = $2;
    // printf("= %d\n> ", loc_exp_dyn_eval_result);
    // free_tree($2);
    // free($2);
    return 0;
    }
  // | eval_tree error EOL { YYABORT; }
  | eval_tree ERROR { YYABORT; }
  | eval_tree error { YYABORT; }
 ;

%%
