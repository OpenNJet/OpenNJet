#include <njt_config.h>
#include <njt_core.h>
#include <njt_http.h>

#if defined(_WIN32) && !defined(__CYGWIN__)
#include <windows.h>
#endif

#include "zlib.h"
#include "njt_doc_module.h"
#include "njt_doc_gz.h"


static char* njt_doc_gunzip(unsigned char* src, unsigned long  src_len, unsigned long* out_len);
static int njt_doc_parseoct(const char *p, size_t n);
static int njt_doc_is_end_of_archive(const char *p);
static void njt_doc_create_dir(char *pathname, int mode);
static FILE * njt_doc_create_file(char *pathname, int mode);
static int njt_doc_verify_checksum(const char *p);
static void njt_doc_untar(unsigned char* in, unsigned long in_len, const char *base);

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
    NULL,                                  /* exit process */
    njt_doc_module_exit,                   /* exit master */
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
    njt_log_error(NJT_LOG_EMERG, cycle->log, 0, "doc module init start ");
    conf = njt_pcalloc(cycle->pool, sizeof(njt_doc_conf_t));
    if (conf == NULL)
    {
		njt_log_error(NJT_LOG_EMERG, cycle->log, 0, "doc module alloc main conf error ");
        return NJT_ERROR;
    }

    //create ramdom dir on /dev/shm/
	njt_uint_t rand_index = njt_random() % 100;

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
	
	cycle->conf_ctx[njt_doc_module.index] = (void *) conf;

	// njt_log_error(NJT_LOG_EMERG, cycle->log, 0, "doc module init start end, index:%d  cycle->conf_ctx:%d  dir:%V",
	                    // njt_doc_module.index, cycle->conf_ctx, conf->untar_dir);

    return NJT_OK;
}

static void njt_doc_module_exit(njt_cycle_t *cycle) {
	njt_doc_conf_t *conf;
	// u_char *dst;
	// u_char *p;
	// size_t len;

	conf = (njt_doc_conf_t *)njt_get_conf(cycle->conf_ctx, njt_doc_module);
	// cycle->conf_ctx[njt_doc_module.index];
	
    //remove dir conf->untar_dir
	if (njt_delete_dir(conf->untar_dir.data) == NJT_FILE_ERROR) {
		njt_log_error(NJT_LOG_EMERG, cycle->log, 0, "doc module remove dir:%V error ", conf->untar_dir);
	}


    return;
}

static char* njt_doc_gunzip(unsigned char* src, unsigned long  src_len, unsigned long* out_len)
{
    // unsigned have;
    z_stream strm;
    link_buf* top=NULL, *parent =NULL, *cur=NULL;
	memset(&strm, 0, sizeof(strm));

	strm.next_in = src;
	strm.avail_in = src_len;

	int rv = inflateInit2(&strm, 15 + 16);
    if (rv != Z_OK)
        return NULL;
	top=malloc(sizeof(link_buf));
	top->next=NULL;
	top->buf=malloc(CHUNK);
	parent=top; cur=top;
    do {
		if (!cur) {
			cur= malloc(sizeof(link_buf));
			cur->buf=malloc(CHUNK);
			cur->next=NULL;
			cur->out_len=0;
			parent->next=cur;
			parent=cur;
			} 
        strm.avail_out = CHUNK;
        strm.next_out = cur->buf;

		cur=NULL;
        rv = inflate(&strm, Z_NO_FLUSH);
		if (rv!=Z_BUF_ERROR &&rv!=Z_OK&&rv!=Z_STREAM_END) {
			//zerr(rv);
			return NULL;
		}
        parent->out_len = CHUNK - strm.avail_out;
    } while (strm.avail_out == 0);
  	inflateEnd(&strm);
	if (rv!=Z_STREAM_END) {
		//todo: free ngx_buf
		return NULL;
	}
   	char *p, *out_buf=malloc(strm.total_out);
	p=out_buf;
	cur=top;
	while (cur) {
		memcpy(p,cur->buf,cur->out_len);
		p+=cur->out_len;
		parent=cur;
		cur=cur->next;
		free(parent->buf);
		free(parent);
	}
	fprintf(stderr,"total:%ld\n",strm.total_out);
	*out_len=strm.total_out;
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

static void njt_doc_create_dir(char *pathname, int mode)
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
			njt_doc_create_dir(pathname, 0755);
			*p = '/';
#if defined(_WIN32) && !defined(__CYGWIN__)
			r = _mkdir(pathname);
#else
			r = mkdir(pathname, mode);
#endif
		}
	}
	if (r != 0)
		fprintf(stderr, "Could not create directory %s\n", pathname);
}


static FILE * njt_doc_create_file(char *pathname, int mode)
{
	fprintf(stderr, "create file %s\n", pathname);
	FILE *f;
	f = fopen(pathname, "wb+");
	if (f == NULL) {
		/* Try creating parent dir and then creating file. */
		char *p = strrchr(pathname, '/');
		if (p != NULL) {
			*p = '\0';
			njt_doc_create_dir(pathname, 0755);
			*p = '/';
			f = fopen(pathname, "wb+");
		}
	}
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

static void njt_doc_untar(unsigned char* in, unsigned long in_len,const char *base)
{
	FILE *f = NULL;
	printf("Extracting to %s\n", base);
	int bytes_left = in_len, filesize;
	char* buff = (char *)in;
	for(;;) {
		if (bytes_left < 512) {
			fprintf(stderr,
			    "Short read on %s: expected 512, got %d\n",
			    base, (int)bytes_left);
			return;
		}
		if (njt_doc_is_end_of_archive(buff)) {
			printf("End of %s\n", base);
			return;
		}
		if (!njt_doc_verify_checksum(buff)) {
			fprintf(stderr, "Checksum failure\n");
			return;
		}
		filesize = njt_doc_parseoct(buff + 124, 12);
		printf(" filesize %d\n", filesize);
		char* full_dir;
		switch (buff[156]) {
		case '1':
			printf(" Ignoring hardlink %s\n", buff);
			break;
		case '2':
			printf(" Ignoring symlink %s\n", buff);
			break;
		case '3':
			printf(" Ignoring character device %s\n", buff);
				break;
		case '4':
			printf(" Ignoring block device %s\n", buff);
			break;
		case '5':
			printf(" Extracting dir %s\n", buff);
			full_dir=malloc(strlen(base)+1+strlen(buff));
			sprintf(full_dir,"%s/%s",base,buff);
			njt_doc_create_dir(full_dir, njt_doc_parseoct(buff + 100, 8));
			free(full_dir);
			filesize = 0;
			break;
		case '6':
			printf(" Ignoring FIFO %s\n", buff);
			break;
		default:
			printf(" Extracting file %s\n", buff);
			full_dir=malloc(strlen(base)+1+strlen(buff));

			sprintf(full_dir,"%s/%s",base,buff);
			f = njt_doc_create_file(full_dir, njt_doc_parseoct(buff + 100, 8));
			free(full_dir);
			break;
		}
		buff+=512;
	    bytes_left-=512;	
		while (filesize > 0) {
			int bytes_proc=512;
			bytes_left-=512;
			if (filesize<512) bytes_proc=filesize;
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
    // njt_str_t *value;
    unsigned long out_len;
    char* un_data;
	njt_http_core_loc_conf_t *clcf;
    // njt_int_t                   alias;
    // njt_uint_t                  n;
    // njt_http_script_compile_t   sc;
	njt_doc_conf_t              *fconf;
        njt_conf_log_error(NJT_LOG_EMERG, cf, 0,
                           "=============test0 %V",
                           &cmd->name);

	njt_doc_module_create_conf(cf->cycle);
	fconf = (njt_doc_conf_t *)njt_get_conf(cf->cycle->conf_ctx, njt_doc_module);
	    // cf->cycle->conf_ctx[njt_doc_module.index];
    //untar
	un_data = njt_doc_gunzip(doc_tar_gz,doc_tar_gz_len,&out_len);
	if (un_data) {
		njt_doc_untar((unsigned char *)un_data, out_len, (char *)fconf->untar_dir.data);
		njt_free(un_data);
	}else{
        njt_conf_log_error(NJT_LOG_ERR, cf, 0,
                    "doc_untar fail");
    }

    //set root dir
    clcf = njt_http_conf_get_module_loc_conf(cf, njt_http_core_module);

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


/*
    if (clcf->root.data) {
        njt_conf_log_error(NJT_LOG_EMERG, cf, 0,
                           "\"%V\" directive is duplicate, ",
                           &cmd->name);

        return NJT_CONF_ERROR;
    }

    if (clcf->named) {
        njt_conf_log_error(NJT_LOG_EMERG, cf, 0,
                           "the \"alias\" directive cannot be used "
                           "inside the named location");

        return NJT_CONF_ERROR;
    }

    if (njt_strstr(value[1].data, "$document_root")
        || njt_strstr(value[1].data, "${document_root}"))
    {
        njt_conf_log_error(NJT_LOG_EMERG, cf, 0,
                           "the $document_root variable cannot be used "
                           "in the \"%V\" directive",
                           &cmd->name);

        return NJT_CONF_ERROR;
    }

    if (njt_strstr(value[1].data, "$realpath_root")
        || njt_strstr(value[1].data, "${realpath_root}"))
    {
        njt_conf_log_error(NJT_LOG_EMERG, cf, 0,
                           "the $realpath_root variable cannot be used "
                           "in the \"%V\" directive",
                           &cmd->name);

        return NJT_CONF_ERROR;
    }

	alias = 0;
    clcf->alias = alias;
    clcf->root = value[1];

    if (!alias && clcf->root.len > 0
        && clcf->root.data[clcf->root.len - 1] == '/')
    {
        clcf->root.len--;
    }

    if (clcf->root.data[0] != '$') {
        if (njt_conf_full_name(cf->cycle, &clcf->root, 0) != NJT_OK) {
            return NJT_CONF_ERROR;
        }
    }

    n = njt_http_script_variables_count(&clcf->root);

    njt_memzero(&sc, sizeof(njt_http_script_compile_t));
    sc.variables = n;

#if (NJT_PCRE)
    if (alias && clcf->regex) {
        clcf->alias = NJT_MAX_SIZE_T_VALUE;
        n = 1;
    }
#endif

    if (n) {
        sc.cf = cf;
        sc.source = &clcf->root;
        sc.lengths = &clcf->root_lengths;
        sc.values = &clcf->root_values;
        sc.complete_lengths = 1;
        sc.complete_values = 1;

        if (njt_http_script_compile(&sc) != NJT_OK) {
            return NJT_CONF_ERROR;
        }
    }
	*/
        njt_conf_log_error(NJT_LOG_EMERG, cf, 0,
                           "=============test %V",
                           &cmd->name);
    return NJT_CONF_OK;
}

/*
static void *njt_doc_create_main_conf(njt_conf_t *cf) 
{
    njt_doc_conf_t *conf;

    conf = njt_pcalloc(cf->pool, sizeof(njt_doc_conf_t));
    if (conf == NULL)
    {
        return NULL;
    }

    conf->untar_dir.data = NULL;
    conf->untar_dir.len = 0;

    return conf;
}

static char *njt_doc_init_main_conf(njt_conf_t *cf, void *conf)
{
    return NJT_CONF_OK;
}
*/
