// define base datatype used in parser
#ifndef _LOC_EVAL_H
#define _LOC_EVAL_H
#include <lex.yy.h>
#include <loc_parse.tab.h>
typedef int request_t;
typedef enum {
    LOC_EXPRESSION = 0,
    BOOL_OP_OR,
    BOOL_OP_AND
} loc_parse_node_type;

typedef struct {
    char   *exp;
    int     idx;
} loc_exp_t;
struct loc_parse_node_s {
    int node_type;
    struct loc_parse_node_s *left;
    struct loc_parse_node_s *right;
    loc_exp_t               *loc_exp;
};
typedef struct loc_parse_node_s loc_parse_node_t;

typedef struct {
    loc_parse_node_t *root;
    int               count;
    char**            exps;
} loc_parse_ctx_t; 

loc_exp_t *new_loc_exp(char* exp, int idx);
loc_parse_node_t * new_loc_parse_exp_node(loc_exp_t* exp);
loc_parse_node_t * new_loc_parse_op_node(int op_type, loc_parse_node_t* left, 
                                            loc_parse_node_t* right);
loc_parse_ctx_t * new_loc_parse_ctx(loc_parse_node_t * root);

int eval_loc_parse_tree(loc_parse_node_t * root);
int eval_loc_exp(loc_exp_t *exp);
void dump_tree(loc_parse_node_t* root, int level);
void free_tree(loc_parse_node_t* root);
void free_ctx(loc_parse_ctx_t* ctx);
extern int loc_exp_dyn_eval_result; 
extern loc_parse_node_t *loc_exp_dyn_parse_tree;
#endif // _LOC_EVAL_H
