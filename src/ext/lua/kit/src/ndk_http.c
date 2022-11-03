
njt_uint_t
ndk_http_count_phase_handlers (njt_http_core_main_conf_t *cmcf)
{
    njt_http_phase_handler_t    *ph;
    njt_uint_t                   i;
    
    ph = cmcf->phase_engine.handlers;
    
    for (i=0; ph[i].checker; i++) /* void */;
        
    return  i;        
}


njt_uint_t
ndk_http_parse_request_method (njt_str_t *m)
{
    switch (m->len) {

        case 3:
            
#if (NJT_HAVE_LITTLE_ENDIAN && NJT_HAVE_NONALIGNED)
        {
            u_char    t[4];
            
            njt_memcpy (t, m->data, 3);
            t[3] = ' ';
            
            if (ndk_str3_cmp (t, 'G', 'E', 'T', ' ')) {
                return  NJT_HTTP_GET;
            }

            if (ndk_str3_cmp (t, 'P', 'U', 'T', ' ')) {
                return  NJT_HTTP_PUT;
            }
        }
            
#else

            if (ndk_str3_cmp (m->data, 'G', 'E', 'T', ' ')) {
                return  NJT_HTTP_GET;
            }

            if (ndk_str3_cmp (m->data, 'P', 'U', 'T', ' ')) {
                return  NJT_HTTP_PUT;
            }

#endif
            break;

        case 4:
            
            if  (m->data[1] == 'O') {

                if (ndk_str3Ocmp (m->data, 'P', 'O', 'S', 'T')) {
                    return  NJT_HTTP_POST;
                }

                if (ndk_str3Ocmp (m->data, 'C', 'O', 'P', 'Y')) {
                    return  NJT_HTTP_COPY;
                }

                if (ndk_str3Ocmp (m->data, 'M', 'O', 'V', 'E')) {
                    return  NJT_HTTP_MOVE;
                }

                if (ndk_str3Ocmp (m->data, 'L', 'O', 'C', 'K')) {
                    return  NJT_HTTP_LOCK;
                }

            } else {

                if (ndk_str4cmp (m->data, 'H', 'E', 'A', 'D')) {
                    return  NJT_HTTP_HEAD;
                }
            }

            break;

        case 5:
            
            if (ndk_str5cmp (m->data, 'M', 'K', 'C', 'O', 'L')) {
                return  NJT_HTTP_MKCOL;
            }

            if (ndk_str5cmp (m->data, 'P', 'A', 'T', 'C', 'H')) {
                return  NJT_HTTP_PATCH;
            }

            if (ndk_str5cmp (m->data, 'T', 'R', 'A', 'C', 'E')) {
                return  NJT_HTTP_TRACE;
            }

            break;

        case 6:
            
            if (ndk_str6cmp (m->data, 'D', 'E', 'L', 'E', 'T', 'E')) {
                return  NJT_HTTP_DELETE;
            }

            if (ndk_str6cmp (m->data, 'U', 'N', 'L', 'O', 'C', 'K')) {
                return  NJT_HTTP_UNLOCK;
            }

            break;

        case 7:
            
            if (ndk_str7_cmp (m->data, 'O', 'P', 'T', 'I', 'O', 'N', 'S', ' '))
            {
                return  NJT_HTTP_OPTIONS;
            }

            break;

        case 8:
            
            if (ndk_str8cmp (m->data, 'P', 'R', 'O', 'P', 'F', 'I', 'N', 'D'))
            {
                return  NJT_HTTP_PROPFIND;
            }

            break;

        case 9:
            
            if (ndk_str9cmp (m->data, 'P', 'R', 'O', 'P', 'P', 'A', 'T', 'C', 'H'))
            {
                return  NJT_HTTP_PROPPATCH;
            }

            break;
    }

    return  0;
}