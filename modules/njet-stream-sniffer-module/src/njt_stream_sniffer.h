#ifndef NJT_STREAM_SNIFFER_H
#define NJT_STREAM_SNIFFER_H
// #include <loc_parse.tab.h>
#ifdef __GNUC__
# pragma GCC diagnostic ignored "-Wunused-function"
#endif
#ifdef __clang__
# pragma clang diagnostic ignored "-Wunused-function"
#endif
typedef int request_t;
typedef enum {
    EXP_INVALID = 0,
    EXP_EXPRESSION,
    EXP_BOOL_OP_OR,
    EXP_BOOL_OP_AND
} sniffer_exp_parse_node_type;

typedef void* (*sniffer_malloc_cb_ptr)(size_t len, void* ctx) ;

typedef struct {
    char   *exp;
    int     idx;
} sniffer_exp_t;

struct sniffer_exp_parse_node_s {
    int node_type;
    struct sniffer_exp_parse_node_s *left;
    struct sniffer_exp_parse_node_s *right;
    sniffer_exp_t               *loc_exp;
};
typedef struct sniffer_exp_parse_node_s sniffer_exp_parse_node_t;  //loc_parse_node_t

typedef struct {
    sniffer_exp_parse_node_t *root;
    int               count;
    char**            exps;
    sniffer_malloc_cb_ptr malloc_handler;
    void*             ctx;
} sniffer_parse_ctx_t; 

typedef int (*sniffer_parse_cb_ptr)(void* p1, void* p2) ;
sniffer_exp_t *new_sniffer_exp(char* exp, int idx);
sniffer_exp_parse_node_t * new_sniffer_parse_exp_node(sniffer_exp_t* exp);
sniffer_exp_parse_node_t * new_sniffer_parse_op_node(int op_type, sniffer_exp_parse_node_t* left, 
                                            sniffer_exp_parse_node_t* right);
int eval_sniffer_parse_tree(sniffer_exp_parse_node_t * root, sniffer_parse_cb_ptr handler, void* data);
int eval_sniffer_exp(sniffer_exp_t *exp, void* data);
void dump_sniffer_tree(sniffer_exp_parse_node_t* root, int level);
void free_sniffer_tree(sniffer_exp_parse_node_t* root);
int get_exp_counts(sniffer_exp_parse_node_t *root);
void free_sniffer_bison_tree(sniffer_exp_parse_node_t* root);

#endif
