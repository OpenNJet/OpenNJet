#include <njt_config.h>
#include <njt_core.h>


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

static void *njt_doc_create_conf(njt_cycle_t *cycle);
static char *njt_doc_init_conf(njt_cycle_t *cycle, void *conf);

static char *njt_doc_api_set(njt_conf_t *cf, njt_command_t *cmd, void *conf);

static njt_command_t njt_doc_commands[] = {

    {njt_string("doc_api"),
     NJT_MAIN_CONF |NJT_DIRECT_CONF| NJT_CONF_TAKE1,
     njt_doc_api_set,
     0,     
     0,
     NULL},

    njt_null_command /* command termination */
};

/* The module context. */
static njt_core_module_t njt_doc_module_ctx = {
    njt_string("doc_api"),
    njt_doc_create_conf,
    njt_doc_init_conf
};


/* Module definition. */
njt_module_t  njt_doc_module = {
    NJT_MODULE_V1,
    &njt_doc_module_ctx, /* module context */
    njt_doc_commands,    /* module directives */
    NJT_CORE_MODULE,        /* module type */
    NULL,                                  /* init master */
    NULL,                                  /* init module */
    NULL,                                  /* init process */
    NULL,                                  /* init thread */
    NULL,                                  /* exit thread */
    NULL,                                  /* exit process */
    NULL,                                  /* exit master */
    NJT_MODULE_V1_PADDING
};

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
    njt_str_t *value;
    njt_doc_conf_t *fmcf;
    unsigned long out_len;
    char* un_data;

    value = cf->args->elts;
    fmcf = (njt_doc_conf_t *)conf;

    u_char *dst;
    size_t vl = value[1].len + 1;
    dst = njt_pnalloc(cf->pool, vl);
    if (dst == NULL)
    {
        return NJT_CONF_ERROR;
    }

    njt_memcpy(dst, value[1].data, value[1].len);
    dst[vl-1] = '\0';

    fmcf->untar_dir.data = dst;
    fmcf->untar_dir.len = vl;

    //untar
    
	un_data = njt_doc_gunzip(doc_tar_gz,doc_tar_gz_len,&out_len);
	if (un_data) {
		njt_doc_untar((unsigned char *)un_data, out_len, (char *)fmcf->untar_dir.data);
		njt_free(un_data);
	}else{
        njt_conf_log_error(NJT_LOG_ERR, cf, 0,
                    "doc_untar fail");
    }

    return NJT_CONF_OK;
}


static void *njt_doc_create_conf(njt_cycle_t *cycle) 
{
    njt_doc_conf_t *conf;

    conf = njt_pcalloc(cycle->pool, sizeof(njt_doc_conf_t));
    if (conf == NULL)
    {
        return NULL;
    }

    conf->untar_dir.data = NULL;
    conf->untar_dir.len = 0;

    return conf;
}

static char *njt_doc_init_conf(njt_cycle_t *cycle, void *cf)
{
    return NJT_CONF_OK;
}

