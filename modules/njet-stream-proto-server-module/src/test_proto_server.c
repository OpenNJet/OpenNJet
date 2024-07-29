

int proto_server_process_connetion(tcc_stream_request_t *r) {
    char buffer[1024] = {0};
    char ip[64] = "127.0.0.1"; 
    int ret;
    void *p = malloc(r->addr_text->len + 1);
    memset((void *)p,0,r->addr_text->len + 1);
    memcpy(p,(void *)r->addr_text->data,r->addr_text->len);
    ret = memcmp((void *)r->addr_text->data,ip,strlen(ip));

    if(memcmp((void *)r->addr_text->data,ip,strlen(ip)) == 0) {
	proto_server_log(NJT_LOG_DEBUG,"1 tcc connetion ip=%s,NJT_STREAM_FORBIDDEN !",p);
	free(p);
	return NJT_STREAM_FORBIDDEN;
    } 
    proto_server_log(NJT_LOG_DEBUG,"1 tcc connetion ip=%s ok!",p);
    free(p);
    return NJT_OK;
}
int proto_server_process_preread(tcc_stream_request_t *r) {
    void *p = malloc(r->addr_text->len + 1);
    memset((void *)p,0,r->addr_text->len + 1);
    memcpy(p,(void *)r->addr_text->data,r->addr_text->len);
    proto_server_log(NJT_LOG_DEBUG,"2 tcc preread ip=%s ok!",p);
    free(p);
    return NJT_DECLINED;
}
int proto_server_process_log(tcc_stream_request_t *r) {
    void *p = malloc(r->addr_text->len + 1);
    memset((void *)p,0,r->addr_text->len + 1);
    memcpy(p,(void *)r->addr_text->data,r->addr_text->len);
    proto_server_log(NJT_LOG_DEBUG,"4 tcc log ip=%s ok!",p);
    free(p);
    return NJT_OK;
}
int proto_server_process_message(tcc_stream_request_t *r) {
    char buf[1024] = {0};
    void *p = malloc(r->addr_text->len + 1);
    memset((void *)p,0,r->addr_text->len + 1);
    memcpy(p,(void *)r->addr_text->data,r->addr_text->len);

    proto_server_log(NJT_LOG_DEBUG,"3 tcc content tcc get=%s",r->in_buf.pos);
    snprintf(buf,sizeof(buf),"ret:ip=%s,data=%s\n",p,r->in_buf.pos);
    //proto_server_send(r,buf,strlen(buf));
    proto_server_send_broadcast(r->srv_ctx,buf,strlen(buf));

    return NJT_OK;
}
int proto_server_process_client_update(tcc_stream_request_t *r) {
    char buf[1024] = {0};
    void *p = malloc(r->addr_text->len + 1);
    memset((void *)p,0,r->addr_text->len + 1);
    memcpy(p,(void *)r->addr_text->data,r->addr_text->len);
    if (r->in_buf.last != r->in_buf.pos) {
    snprintf(buf,sizeof(buf),"ret:tcc client  update ip=%s,data %s\n",p,r->in_buf.pos);
    } else {
	snprintf(buf,sizeof(buf),"ret:tcc client update ip=%s\n",p);
    }
    proto_server_send(r,buf,strlen(buf));
    //proto_server_send_broadcast(r->srv_ctx,buf,strlen(buf));

    proto_server_log(NJT_LOG_DEBUG,"%s",buf);
    return NJT_OK;
}

int proto_server_process_connection_abort(tcc_stream_request_t *r) {
    return NJT_OK;
}
int proto_server_update(tcc_stream_server_ctx *srv_ctx) {
   char buf[1024] = "server data\n";
   proto_server_send_broadcast(srv_ctx,buf,strlen(buf));
   proto_server_log(NJT_LOG_DEBUG,"tcc server update!");
   return NJT_OK;
}
