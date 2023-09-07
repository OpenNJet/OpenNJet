#include "njt_http_if_location_lex.h"
#include "njt_http_if_location_api.h"
#include "njt_http_if_location_parse.h"
#include "njt_core.h"
void parse_dyn_loc(char* dyn_loc);
loc_malloc_cb_ptr loc_malloc_handler = NULL;
void*             loc_malloc_ctx = NULL; // pool
void* loc_malloc(size_t size);


void*
loc_malloc(size_t size){
    if (loc_malloc_handler) {
        return (loc_malloc_handler(size, loc_malloc_ctx));
    } else {
        return malloc(size);
    }
}

loc_exp_t* 
new_loc_exp(char *exp, int idx)
{
    loc_exp_t* loc_exp = malloc(sizeof(loc_exp_t));
    if (!loc_exp) {
        // yyerror("")
        exit(0);
    }
    // memcpy xxx
    // free(exp)
    loc_exp->exp = exp;
    loc_exp->idx = idx;
    return loc_exp;
}

loc_parse_node_t* 
new_loc_parse_exp_node(loc_exp_t *exp)
{
    loc_parse_node_t* node = malloc(sizeof(loc_parse_node_t));
    if (!node) {
        exit(0);
    }
    node->node_type = LOC_EXPRESSION;
    node->left = NULL;
    node->right = NULL;
    node->loc_exp = exp;

    return node;
}


loc_parse_node_t* 
new_loc_parse_op_node(int op_type, loc_parse_node_t* left, loc_parse_node_t* right)
{
    loc_parse_node_t* node = malloc(sizeof(loc_parse_node_t));
    if (!node) {
        exit(1);
    }
    node->node_type = op_type; // check value ??
    node->left = left;
    node->right = right;
    node->loc_exp = NULL;

    return node;
}


// create ctx from the ast tree
loc_parse_ctx_t* 
new_loc_parse_ctx(loc_parse_node_t *root){
    char** exps;
    loc_parse_ctx_t* ctx;
    int idx = 0;
    int count = 0;
    loc_parse_node_t** stack;

    // get exp count in ast tree;
    count = get_exp_counts(root);
    exps = malloc(sizeof(char *)*count);
    if (!exps) {
        exit(1);
    }
    ctx = malloc(sizeof(loc_parse_ctx_t));
    if (!ctx) {
        exit(1);
    }
    stack = malloc(sizeof(loc_parse_node_t*)*count);
    if (!stack) {
        exit(1);
    }

    loc_parse_node_t* current = root;
    int stack_size = 0;
 
    njt_log_error(NJT_LOG_DEBUG, njt_cycle->log, 0,"count: %d \n", count);
    // printf("start traverse tree \n");
    while (current != NULL || stack_size != 0) {
        if (current != NULL) {
            stack[stack_size] = current;
            stack_size++;
            // printf("stack_size: %d\n", stack_size);
            current = current->left;
        } else {
            current = stack[stack_size-1];
            stack_size--;
            // printf("stack_size: %d\n", stack_size);
            // printf("type: %d\n", current->node_type);
            if (current->node_type == LOC_EXPRESSION) {
                if(idx != current->loc_exp->idx) {
                    printf("idx: %d,  idx_exp: %d \n", idx, current->loc_exp->idx);
                } 
                // printf("correct: idx: %d,  idx_exp: %d \n", idx, current->loc_exp->idx);
                exps[idx] = current->loc_exp->exp;
                idx++;
            }
            current = current->right;
        }
    }

    free(stack);

    ctx->root = root;
    ctx->exps = exps;
    ctx->count = count;

    return ctx;
}

int get_exp_counts(loc_parse_node_t* root) {
    if (!root) return 0;
    if (root->node_type == LOC_EXPRESSION) {
        return 1;
    } 
    return get_exp_counts(root->left) + get_exp_counts(root->right);
}

int
eval_loc_parse_tree(loc_parse_node_t * root, loc_parse_cb_ptr handler, void * data)
{
    switch (root->node_type)
    {
    case LOC_EXPRESSION:
        if(handler){
            return handler(root->loc_exp, data);
        } else {      
            return eval_loc_exp(root->loc_exp, data);
        }
        break;
    case BOOL_OP_OR:
        return   eval_loc_parse_tree(root->left, handler, data) 
               ? 1 : eval_loc_parse_tree(root->right, handler, data);
        break;
    case BOOL_OP_AND:
        return   eval_loc_parse_tree(root->left, handler, data) 
               ? eval_loc_parse_tree(root->right, handler, data) : 0;
        break;
    default:
        // yyerror()
        break;
    } 
    // unreachable
    return 0;
}


int
eval_loc_exp(loc_exp_t *exp, void* data){
    if (!exp) {
        //yyerror()
        return 0;
    }
    // call njt_xxx
    printf("exp: %s, %d \n", exp->exp, (exp->exp[1] > 'm') ? 1 : 0);
    return (exp->exp[1] > 'm') ? 1 : 0;
}


void 
dump_tree(loc_parse_node_t* root, int level) 
{
	int i;

	if (!root) return;
	
    if  (root->left) {
		dump_tree(root->left, level+1);
	}

	for (i=0;i<level;i++) {
        njt_log_error(NJT_LOG_DEBUG, njt_cycle->log, 0,"\t");
    }
    switch (root->node_type)
    {
    case LOC_EXPRESSION:
        njt_log_error(NJT_LOG_DEBUG, njt_cycle->log, 0,"%s, idx: %d", root->loc_exp->exp, root->loc_exp->idx);
        break;
    case BOOL_OP_OR:
        njt_log_error(NJT_LOG_DEBUG, njt_cycle->log, 0,"OR");
        break;
    case BOOL_OP_AND:
        njt_log_error(NJT_LOG_DEBUG, njt_cycle->log, 0,"AND\n");
        break;
    
    default:
        break;
    }
	if  (root->right) {
		dump_tree(root->right, level+1);
	}
}


void 
free_exp(loc_exp_t* exp) {
    if (exp) {
        free(exp->exp);
        free(exp);
    }
}

void 
free_tree(loc_parse_node_t* root)
{
    if (!root) return;
    // if (root->loc_exp) free_exp(root->loc_exp);
    // if (root->left) free_tree(root->left);
    // if (root->right) free_tree(root->right);
    // free(root);
  
    switch (root->node_type)
    {
    case LOC_EXPRESSION:
        free_exp(root->loc_exp);
        break;
    case BOOL_OP_AND: case BOOL_OP_OR:
        free_tree(root->left);
        free_tree(root->right);
        break;
    default:
        printf("internal error: free bad node %d\n", root->node_type);
        break;
    }
    free(root);
}
void free_bison_tree(loc_parse_node_t* root){
     if (!root) return;
     free_tree(root);
}
void
free_ctx(loc_parse_ctx_t* ctx) {
    free(ctx->exps);
    free(ctx);
}


extern int loc_exp_dyn_eval_result; // eval result
extern loc_parse_node_t *loc_exp_dyn_parse_tree; // binary bool expression tree
extern int yy_flex_debug;
void parse_dyn_loc(char* dyn_loc) {
    int r;
    loc_parse_ctx_t* ctx;
    loc_parse_node_t* tree_root = NULL;
    yylex_destroy();
    yy_scan_string(dyn_loc);
    yy_flex_debug = 0;
    r = yyparse(&tree_root);
    if (r) {
        // error in parsing
        return;
    }
    if(!tree_root) {
        return;
    }
    ctx = new_loc_parse_ctx(loc_exp_dyn_parse_tree);
    eval_loc_parse_tree(loc_exp_dyn_parse_tree, NULL, (void*)&r);
    dump_tree(loc_exp_dyn_parse_tree, 0);
    dump_tree(tree_root, 0);
    free_tree(loc_exp_dyn_parse_tree);
    free_ctx(ctx);
}

