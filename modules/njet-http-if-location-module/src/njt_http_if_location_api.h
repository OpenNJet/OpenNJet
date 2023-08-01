// define base datatype used in parser
#ifndef _NJT_HTTP_IF_LOCATION_API_H
#define _NJT_HTTP_IF_LOCATION_API_H
// #include <loc_parse.tab.h>
#ifdef __GNUC__
# pragma GCC diagnostic ignored "-Wunused-function"
#endif
#ifdef __clang__
# pragma clang diagnostic ignored "-Wunused-function"
#endif
typedef int request_t;
typedef enum {
    INVALID = 0,
    LOC_EXPRESSION,
    BOOL_OP_OR,
    BOOL_OP_AND
} loc_parse_node_type;

typedef void* (*loc_malloc_cb_ptr)(size_t len, void* ctx) ;

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
    loc_malloc_cb_ptr malloc_handler;
    void*             ctx;
} loc_parse_ctx_t; 

void* loc_malloc(size_t len);
typedef int (*loc_parse_cb_ptr)(void* p1, void* p2) ;
loc_exp_t *new_loc_exp(char* exp, int idx);
loc_parse_node_t * new_loc_parse_exp_node(loc_exp_t* exp);
loc_parse_node_t * new_loc_parse_op_node(int op_type, loc_parse_node_t* left, 
                                            loc_parse_node_t* right);
loc_parse_ctx_t * new_loc_parse_ctx(loc_parse_node_t * root);

int eval_loc_parse_tree(loc_parse_node_t * root, loc_parse_cb_ptr handler, void* data);
int eval_loc_exp(loc_exp_t *exp, void* data);
void dump_tree(loc_parse_node_t* root, int level);
void free_tree(loc_parse_node_t* root);
void free_ctx(loc_parse_ctx_t* ctx);
int get_exp_counts(loc_parse_node_t *root);
void free_bison_tree(loc_parse_node_t* root);

#endif //  _NJT_HTTP_IF_LOCATION_API_H
