%{
#  include <stdio.h>
#  include <stdlib.h>
#  include "njt_stream_sniffer.h"
int snifferlex();
void sniffererror(sniffer_exp_parse_node_t **tree_root,  const char * s);

sniffer_exp_parse_node_t *sniffer_exp_dyn_parse_tree;
%}

%union {
  sniffer_exp_parse_node_t *node;
  sniffer_exp_t *loc_exp;
}



%parse-param { sniffer_exp_parse_node_t **tree_root }
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
/* %destructor {free_sniffer_tree($$);} <node> */
%destructor {  /*printf ("Discarding symbol: OR at line %d\n", @$.first_line);*/ } OR
%destructor {  /*printf ("Discarding symbol: AND at line %d\n", @$.first_line);*/ } AND
/* %destructor { printf ("Discarding symbol: EOL at line %d\n", @$.first_line); } EOL */
%destructor {  /*printf ("Discarding symbol: ERROR at line %d\n", @$.first_line);*/ } ERROR 
%destructor { if($$) { free_sniffer_tree ($$); /*printf ("Discarding symbol: exp at line %d\n", @$.first_line);*/ } } exp
%destructor { if($$) { free_sniffer_tree ($$); /*printf ("Discarding symbol: eval_tree at line %d\n", @$.first_line);*/ } } eval_tree


%%

exp:   {/*printf("BISON NULL_EXP: \n");*/ $$=NULL; YYABORT;}
   | LOC_EXP {  /*printf("BISON: LOC_EXP\n");*/ $$ = new_sniffer_parse_exp_node($1); }
   | '(' exp ')'          { /*printf("BISON: (EXP) \n");*/ $$ = $2; }
   | exp OR  exp          { /*printf("BISON: OR \n");*/ $$ = new_sniffer_parse_op_node(EXP_BOOL_OP_OR, $1,$3); }
   | exp AND exp          { /*printf("BISON: AND \n");*/$$ = new_sniffer_parse_op_node(EXP_BOOL_OP_AND, $1,$3);}

eval_tree: {$$ = NULL; }/* nothing */
  | eval_tree exp YYEOF {
    dump_sniffer_tree($2, 0);
    sniffer_exp_dyn_parse_tree = $2;
    *tree_root = $2;
    return 0;
    }
  | eval_tree ERROR { YYABORT; }
  | eval_tree error { YYABORT; }
 ;

%%

sniffer_exp_parse_node_t* 
new_sniffer_parse_exp_node(sniffer_exp_t *exp)
{
    sniffer_exp_parse_node_t* node = malloc(sizeof(sniffer_exp_parse_node_t));
    if (!node) {
        exit(0);
    }
    node->node_type = EXP_EXPRESSION;
    node->left = NULL;
    node->right = NULL;
    node->loc_exp = exp;

    return node;
}

sniffer_exp_parse_node_t* 
new_sniffer_parse_op_node(int op_type, sniffer_exp_parse_node_t* left, sniffer_exp_parse_node_t* right)
{
    sniffer_exp_parse_node_t* node = malloc(sizeof(sniffer_exp_parse_node_t));
    if (!node) {
        exit(1);
    }
    node->node_type = op_type; // check value ??
    node->left = left;
    node->right = right;
    node->loc_exp = NULL;

    return node;
}