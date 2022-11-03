

/* TODO : check that this is correct */

u_char *
ndk_map_uri_to_path_add_suffix (njt_http_request_t *r, njt_str_t *path, njt_str_t *suffix, njt_int_t dot)
{
    size_t      root_size;
    u_char     *p;

    if (suffix->len) {

        if (dot) {

            p = njt_http_map_uri_to_path (r, path, &root_size, suffix->len + 1);

            if (p == NULL)
                return  NULL;

            *p = '.';
            p++;

        } else {

            p = njt_http_map_uri_to_path (r, path, &root_size, suffix->len);

            if (p == NULL)
                return  NULL;
        }       

        path->len--;

        p = njt_cpymem (p, suffix->data, suffix->len);
        *p = '\0';

        return  p;  
    }

    p = njt_http_map_uri_to_path (r, path, &root_size, 0);

    path->len--;

    return  p;
}

