
njt_int_t
ndk_copy_chain_to_str (njt_pool_t *pool, njt_chain_t *in, njt_str_t *str)
{
    njt_chain_t     *cl;
    size_t           len;
    u_char          *p;
    njt_buf_t       *b;
    
    len = 0;
    for (cl = in; cl; cl = cl->next)
        len += njt_buf_size (cl->buf);
    
    ndk_palloc_re (p, pool, len + 1);
    
    str->data = p;
    str->len = len;
    
    for (cl = in; cl; cl = cl->next) {
        
        b = cl->buf;
        
        if (njt_buf_in_memory (b)) {
            p = njt_cpymem (p, b->pos, b->last - b->pos);
        }
    }
    
    *p = '\0';
    
    return  NJT_OK;
}


char *
ndk_copy_chain_to_charp (njt_pool_t *pool, njt_chain_t *in)
{
    njt_str_t   str;
    
    if (ndk_copy_chain_to_str (pool, in, &str) != NJT_OK)
        return  NULL;
    
    return  (char *) str.data;
}