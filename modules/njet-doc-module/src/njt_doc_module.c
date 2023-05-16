
/*
 * Copyright (C) 2021-2023  TMLake(Beijing) Technology Co., Ltd.
 */


#include <njt_config.h>
#include <njt_core.h>
#include <njt_http.h>

#if defined(_WIN32) && !defined(__CYGWIN__)
#include <windows.h>
#endif

#include "zlib.h"
#include "njt_doc_module.h"
#include "njt_doc_gz.h"


static char* njt_doc_gunzip(njt_conf_t *cf, unsigned char* src, unsigned long  src_len, unsigned long* out_len);
static int njt_doc_parseoct(const char *p, size_t n);
static int njt_doc_is_end_of_archive(const char *p);
static void njt_doc_create_dir(njt_conf_t *cf, char *pathname, int mode);
static FILE * njt_doc_create_file(njt_conf_t *cf, char *pathname, int mode);
static int njt_doc_verify_checksum(const char *p);
static void njt_doc_untar(njt_conf_t *cf, unsigned char* in, unsigned long in_len, const char *base);

int njt_doc_delete_dir(njt_pool_t *pool, const char *path);

static njt_int_t njt_doc_module_init(njt_cycle_t *cycle);
static njt_int_t njt_doc_module_create_conf(njt_cycle_t *cycle);
static void njt_doc_module_exit(njt_cycle_t *cycle);
/*
static void *njt_doc_create_main_conf(njt_conf_t *cf);
static char *njt_doc_init_main_conf(njt_conf_t *cf, void *conf);
*/
static char *njt_doc_api_set(njt_conf_t *cf, njt_command_t *cmd, void *conf);

static njt_command_t njt_doc_commands[] = {

    {njt_string("doc_api"),
     NJT_HTTP_LOC_CONF | NJT_CONF_NOARGS,
     njt_doc_api_set,
     0,     
     0,
     NULL},

    njt_null_command /* command termination */
};

/* The module context. */
static njt_http_module_t njt_doc_module_ctx = {
	NULL,                                   /* preconfiguration */
	NULL,                                   /* postconfiguration */

	NULL,                                   /* create main configuration */
	NULL,                                   /* init main configuration */

	NULL,                                  /* create server configuration */
	NULL,                                  /* merge server configuration */

	NULL,                                   /* create location configuration */
	NULL                                    /* merge location configuration */
};


/* Module definition. */
njt_module_t  njt_doc_module = {
    NJT_MODULE_V1,
    &njt_doc_module_ctx, /* module context */
    njt_doc_commands,    /* module directives */
    NJT_HTTP_MODULE,        /* module type */
    NULL,                                  /* init master */
    njt_doc_module_init,                   /* init module */
    NULL,                                  /* init process */
    NULL,                                  /* init thread */
    NULL,                                  /* exit thread */
    njt_doc_module_exit,                   /* exit process */
    NULL,                                  /* exit master */
    NJT_MODULE_V1_PADDING
};

static njt_int_t njt_doc_module_init(njt_cycle_t *cycle){

    return NJT_OK;
}

static njt_int_t njt_doc_module_create_conf(njt_cycle_t *cycle) {
	njt_doc_conf_t *conf;
	u_char *dst;
	u_char *p;
	size_t len;
    njt_uint_t rand_index;

    conf = njt_pcalloc(cycle->pool, sizeof(njt_doc_conf_t));
    if (conf == NULL)
    {
		njt_log_error(NJT_LOG_EMERG, cycle->log, 0, "doc module alloc main conf error ");
        return NJT_ERROR;
    }

    //create ramdom dir on /dev/shm/
	// rand_index = njt_random() % 1000;
	// now just use a fixed value
	rand_index = 1;

    len = 100;
    dst = njt_pnalloc(cycle->pool, len);
    if (dst == NULL)
    {
		njt_log_error(NJT_LOG_EMERG, cycle->log, 0, "doc module alloc dst dir error ");
        return NJT_ERROR;
    }

	p = njt_snprintf(dst, len, "/dev/shm/njt_doc_%d", rand_index);
	dst[p-dst] = '\0';

    conf->untar_dir.data = dst;
    conf->untar_dir.len = p - dst;
	
	cycle->conf_ctx[njt_doc_module.index] = (void *)conf;

    return NJT_OK;
}

static void njt_doc_module_exit(njt_cycle_t *cycle) {
	// njt_doc_conf_t *conf;

	// conf = (njt_doc_conf_t *)njt_get_conf(cycle->conf_ctx, njt_doc_module);
    // if(conf == NULL){
	// 	njt_log_error(NJT_LOG_EMERG, cycle->log, 0, "doc_api get module conf error");
	// 	return ;
	// }

    // //check dir exist, if exist, delete first
	// if(access((char *)conf->untar_dir.data, 0) != -1){
    //     if (njt_doc_delete_dir(cycle->pool, (char *)conf->untar_dir.data) == NJT_FILE_ERROR) {
    //         njt_log_error(NJT_LOG_EMERG, cycle->log, 0, "doc module remove dir:%s error ", conf->untar_dir.data);
	//     }
	// }

    return;
}


int njt_doc_delete_dir(njt_pool_t *pool, const char *path)
{
    DIR *d = opendir(path);
    size_t path_len = strlen(path);
    int r = -1;
    if (d)
    {
        struct dirent *p;
        r = 0;
        while (!r)
        {
			p = readdir(d);
			if(p == NULL){
				break;
			}
            int r2 = -1;
            char *buf;
            size_t len;
            /* Skip the names "." and ".." as we don't want to recurse on them. */
            if (!strcmp(p->d_name, ".") || !strcmp(p->d_name, ".."))
            {
                continue;
            }
            len = path_len + strlen(p->d_name) + 2;
            buf = njt_pcalloc(pool, len);
            if (buf)
            {
                struct stat statbuf;
                snprintf(buf, len, "%s/%s", path, p->d_name);
                if (!stat(buf, &statbuf))
                {
                    if (S_ISDIR(statbuf.st_mode))
                    {
                        r2 = njt_doc_delete_dir(pool, buf);
                    }
                    else
                    {
                        r2 = unlink(buf);
                    }
                }
                njt_pfree(pool, buf);
            }
            r = r2;
        }
        closedir(d);
    }
    if (!r)
    {
        r = rmdir(path);
    }
    return r;
}


static char* njt_doc_gunzip(njt_conf_t *cf, unsigned char *src,
                      unsigned long  src_len, unsigned long *out_len)
{
    // unsigned have;
    z_stream strm;
    link_buf *top = NULL, *parent = NULL, *cur = NULL;
	memset(&strm, 0, sizeof(strm));

	strm.next_in = src;
	strm.avail_in = src_len;

	int rv = inflateInit2(&strm, 15 + 16);
    if (rv != Z_OK){
        return NULL;
	}
        
	top = njt_pcalloc(cf->pool, sizeof(link_buf));
	if(top == NULL){
		return NULL;
	}

	top->next = NULL;
	top->buf = njt_pcalloc(cf->pool, CHUNK);
	if(top->buf == NULL){
		njt_pfree(cf->pool, top);
		return NULL;
	}

	parent = top;
	cur = top;
    do {
		if (cur == NULL) {
			cur = njt_pcalloc(cf->pool, sizeof(link_buf));
            if(cur == NULL){
                return NULL;
            }

			cur->buf = njt_pcalloc(cf->pool, CHUNK);
			if(cur->buf == NULL){
                return NULL;
            }

			cur->next = NULL;
			cur->out_len = 0;
			parent->next = cur;
			parent = cur;
		}

        strm.avail_out = CHUNK;
        strm.next_out = cur->buf;

		cur = NULL;
        rv = inflate(&strm, Z_NO_FLUSH);
		if (rv != Z_BUF_ERROR && rv != Z_OK && rv != Z_STREAM_END) {
			//zerr(rv);
			return NULL;
		}
        parent->out_len = CHUNK - strm.avail_out;
    } while (strm.avail_out == 0);

  	inflateEnd(&strm);
	if (rv != Z_STREAM_END) {
		//todo: free ngx_buf
		return NULL;
	}
   	char *p, *out_buf = njt_pcalloc(cf->pool, strm.total_out);
	p = out_buf;
	cur = top;
	while (cur) {
		memcpy(p,cur->buf,cur->out_len);
		p += cur->out_len;
		parent = cur;
		cur = cur->next;
		njt_pfree(cf->pool, parent->buf);
		njt_pfree(cf->pool, parent);
	}

	*out_len = strm.total_out;

	return out_buf;
}


static int njt_doc_parseoct(const char *p, size_t n)
{
	int i = 0;

	while ((*p < '0' || *p > '7') && n > 0) {
		++p;
		--n;
	}
	while (*p >= '0' && *p <= '7' && n > 0) {
		i *= 8;
		i += *p - '0';
		++p;
		--n;
	}
	return (i);
}

/* Returns true if this is 512 zero bytes. */
static int njt_doc_is_end_of_archive(const char *p)
{
	int n;
	for (n = 511; n >= 0; --n)
		if (p[n] != '\0')
			return (0);
	return (1);
}

static void njt_doc_create_dir(njt_conf_t *cf, char *pathname, int mode)
{
	char *p;
	int r;

	/* Strip trailing '/' */
	if (pathname[strlen(pathname) - 1] == '/')
		pathname[strlen(pathname) - 1] = '\0';

	/* Try creating the directory. */
#if defined(_WIN32) && !defined(__CYGWIN__)
	r = _mkdir(pathname);
#else
	r = mkdir(pathname, mode);
#endif

	if (r != 0) {
		/* On failure, try creating parent directory. */
		p = strrchr(pathname, '/');
		if (p != NULL) {
			*p = '\0';
			njt_doc_create_dir(cf, pathname, 0755);
			*p = '/';
#if defined(_WIN32) && !defined(__CYGWIN__)
			r = _mkdir(pathname);
#else
			r = mkdir(pathname, mode);
#endif
		}
	}
	if (r != 0){
		njt_log_error(NJT_LOG_DEBUG, cf->cycle->log, 0,
		    "Could not create directory %s", pathname);
	}
}


static FILE * 
njt_doc_create_file(njt_conf_t *cf, char *pathname, int mode)
{
	FILE *f;
	f = fopen(pathname, "wb+");
	if (f == NULL) {
		/* Try creating parent dir and then creating file. */
		char *p = strrchr(pathname, '/');
		if (p != NULL) {
			*p = '\0';
			njt_doc_create_dir(cf, pathname, 0755);
			*p = '/';
			f = fopen(pathname, "wb+");
		}
	}

    njt_log_error(NJT_LOG_DEBUG, cf->cycle->log, 0,
		    "create file %s", pathname);

	return (f);
}

/* Verify the tar checksum. */
static int njt_doc_verify_checksum(const char *p)
{
	int n, u = 0;
	for (n = 0; n < 512; ++n) {
		if (n < 148 || n > 155)
			/* Standard tar checksum adds unsigned bytes. */
			u += ((unsigned char *)p)[n];
		else
			u += 0x20;

	}
	return (u == njt_doc_parseoct(p + 148, 8));
}

static void njt_doc_untar(njt_conf_t *cf, unsigned char* in,
                unsigned long in_len, const char *base)
{
	FILE *f = NULL;
	njt_log_error(NJT_LOG_DEBUG, cf->cycle->log, 0, "Extracting to %s", base);
	int bytes_left = in_len, filesize;
	char* buff = (char *)in;
	for(;;) {
		if (bytes_left < 512) {
            njt_log_error(NJT_LOG_EMERG, cf->cycle->log, 0,
			    "Short read: expected 512, got %d",
				(int)bytes_left);
			return;
		}
		if (njt_doc_is_end_of_archive(buff)) {
			njt_log_error(NJT_LOG_DEBUG, cf->cycle->log, 0,
			    "End of doc untar");
			return;
		}
		if (!njt_doc_verify_checksum(buff)) {
            njt_log_error(NJT_LOG_EMERG, cf->cycle->log, 0,
			    "Checksum failure");
			return;
		}
		filesize = njt_doc_parseoct(buff + 124, 12);
		char* full_dir;
		switch (buff[156]) {
		case '1':
			njt_log_error(NJT_LOG_DEBUG, cf->cycle->log, 0,
			    " Ignoring hardlink");
			break;
		case '2':
			njt_log_error(NJT_LOG_DEBUG, cf->cycle->log, 0,
			    " Ignoring symlink");
			break;
		case '3':
			njt_log_error(NJT_LOG_DEBUG, cf->cycle->log, 0,
			    " Ignoring character device");
			break;
		case '4':
			njt_log_error(NJT_LOG_DEBUG, cf->cycle->log, 0,
			    " Ignoring block device");
			break;
		case '5':
			njt_log_error(NJT_LOG_DEBUG, cf->cycle->log, 0,
			    " Extracting dir");
			full_dir = njt_pcalloc(cf->pool, strlen(base)+2+strlen(buff));
			njt_memzero(full_dir, strlen(base)+2+strlen(buff));
			sprintf(full_dir,"%s/%s",base,buff);
			njt_doc_create_dir(cf, full_dir, njt_doc_parseoct(buff + 100, 8));
			njt_pfree(cf->pool, full_dir);
			filesize = 0;
			break;
		case '6':
			njt_log_error(NJT_LOG_DEBUG, cf->cycle->log, 0,
			    " Ignoring FIFO");
			break;
		default:
			// njt_log_error(NJT_LOG_EMERG, cf->cycle->log, 0,
			//     " Extracting file %s", buff);
			full_dir = njt_pcalloc(cf->pool, strlen(base)+2+strlen(buff));
			njt_memzero(full_dir, strlen(base)+2+strlen(buff));

			sprintf(full_dir,"%s/%s",base,buff);
			f = njt_doc_create_file(cf, full_dir, njt_doc_parseoct(buff + 100, 8));
			njt_pfree(cf->pool, full_dir);
			break;
		}
		buff += 512;
	    bytes_left -= 512;	
		while (filesize > 0) {
			int bytes_proc = 512;
			bytes_left -= 512;
			if (filesize < 512){
				bytes_proc=filesize;
			}

			filesize-=512;
			if (f != NULL) {
                int fwrite_size = (int)fwrite(buff,1,bytes_proc,f);
				if (bytes_proc != fwrite_size) {
						fprintf(stderr, "Failed write\n");
						fclose(f);
						f = NULL;
					}
			}
            buff+=512;
		}
		if (f != NULL) {
			fclose(f);
			f = NULL;
		}
	}
}

static char *
njt_doc_api_set(njt_conf_t *cf, njt_command_t *cmd, void *conf)
{
    unsigned long            out_len;
    char                     *un_data;
	njt_http_core_loc_conf_t *clcf;
	njt_doc_conf_t           *fconf;
	njt_int_t                rc;
	
	njt_log_error(NJT_LOG_NOTICE, cf->cycle->log, 0, "doc_api doc start");
    rc = njt_doc_module_create_conf(cf->cycle);
	if(rc != NJT_OK){
		njt_log_error(NJT_LOG_EMERG, cf->cycle->log, 0, "doc_api create conf error");
		return NJT_CONF_ERROR;
	}
	fconf = (njt_doc_conf_t *)njt_get_conf(cf->cycle->conf_ctx, njt_doc_module);

    if(fconf == NULL){
		njt_log_error(NJT_LOG_EMERG, cf->cycle->log, 0, "doc_api get module conf error");
		return NJT_CONF_ERROR;
	}

    //check dir exist, if exist, delete first
	if(access((char *)fconf->untar_dir.data, 0) != -1){
		//if exist do nothing
		njt_log_error(NJT_LOG_NOTICE, cf->cycle->log, 0, "doc_api doc end, exist");

        // if (njt_doc_delete_dir(cf->pool, (char *)fconf->untar_dir.data) == NJT_FILE_ERROR) {
        //     njt_log_error(NJT_LOG_EMERG, cf->cycle->log, 0, "doc module remove dir:%s error ", fconf->untar_dir.data);
	    // }
	}else{
		//untar
		un_data = njt_doc_gunzip(cf, doc_tar_gz, doc_tar_gz_len, &out_len);
		if (un_data != NULL) {
			njt_doc_untar(cf, (unsigned char *)un_data, out_len, (char *)fconf->untar_dir.data);
			njt_pfree(cf->pool, un_data);
		}else{
			njt_conf_log_error(NJT_LOG_ERR, cf, 0,
						"doc_untar fail");
			return NJT_CONF_ERROR;
		}
	}



    //set root dir
    clcf = njt_http_conf_get_module_loc_conf(cf, njt_http_core_module);
    if(clcf == NULL){
		return NJT_CONF_ERROR;
	}

    clcf->alias = 0;
    clcf->root = fconf->untar_dir;

    if (clcf->root.len > 0
        && clcf->root.data[clcf->root.len - 1] == '/')
    {
        clcf->root.len--;
    }

    if (clcf->root.data[0] != '$') {
        if (njt_conf_full_name(cf->cycle, &clcf->root, 0) != NJT_OK) {
            return NJT_CONF_ERROR;
        }
    }


    return NJT_CONF_OK;
}
