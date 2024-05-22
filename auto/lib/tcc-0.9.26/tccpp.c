/*
 *  TCC - Tiny C Compiler
 * 
 *  Copyright (c) 2001-2004 Fabrice Bellard
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 */

#include "tcc.h"

/********************************************************/
/* global variables */

ST_DATA int tok_flags;
ST_DATA int parse_flags;

ST_DATA struct BufferedFile *file;
ST_DATA int ch, tok;
ST_DATA CValue tokc;
ST_DATA const int *macro_ptr;
ST_DATA CString tokcstr; /* current parsed string, if any */

/* display benchmark infos */
ST_DATA int total_lines;
ST_DATA int total_bytes;
ST_DATA int tok_ident;
ST_DATA TokenSym **table_ident;

ST_DATA TinyAlloc *toksym_alloc;
ST_DATA TinyAlloc *tokstr_alloc;
ST_DATA TinyAlloc *cstr_alloc;

/* ------------------------------------------------------------------------- */

static TokenSym *hash_ident[TOK_HASH_SIZE];
static char token_buf[STRING_MAX_SIZE + 1];
static CString cstr_buf;
static TokenString tokstr_buf;
static unsigned char isidnum_table[256 - CH_EOF];
static int pp_debug_tok, pp_debug_symv;
static void tok_print(const char *msg, const int *str);

/* isidnum_table flags: */
#define IS_SPC 1
#define IS_ID  2
#define IS_NUM 4

static TokenString *macro_stack;

static const char tcc_keywords[] = 
#define DEF(id, str) str "\0"
#include "tcctok.h"
#undef DEF
;

/* WARNING: the content of this string encodes token numbers */
static const unsigned char tok_two_chars[] =
/* outdated -- gr
    "<=\236>=\235!=\225&&\240||\241++\244--\242==\224<<\1>>\2+=\253"
    "-=\255*=\252/=\257%=\245&=\246^=\336|=\374->\313..\250##\266";
*/{
    '<','=', TOK_LE,
    '>','=', TOK_GE,
    '!','=', TOK_NE,
    '&','&', TOK_LAND,
    '|','|', TOK_LOR,
    '+','+', TOK_INC,
    '-','-', TOK_DEC,
    '=','=', TOK_EQ,
    '<','<', TOK_SHL,
    '>','>', TOK_SAR,
    '+','=', TOK_A_ADD,
    '-','=', TOK_A_SUB,
    '*','=', TOK_A_MUL,
    '/','=', TOK_A_DIV,
    '%','=', TOK_A_MOD,
    '&','=', TOK_A_AND,
    '^','=', TOK_A_XOR,
    '|','=', TOK_A_OR,
    '-','>', TOK_ARROW,
    '.','.', 0xa8, // C++ token ?
    '#','#', TOK_TWOSHARPS,
    0
};

static void next_nomacro_spc(void);

ST_FUNC void skip(int c)
{
    if (tok != c)
        tcc_error("'%c' expected (got \"%s\")", c, get_tok_str(tok, &tokc));
    next();
}

ST_FUNC void expect(const char *msg)
{
    tcc_error("%s expected", msg);
}

ST_FUNC void begin_macro(TokenString *str, int alloc)
{
    str->alloc = alloc;
    str->prev = macro_stack;
    str->prev_ptr = macro_ptr;
    macro_ptr = str->str;
    macro_stack = str;
}

ST_FUNC void end_macro(void)
{
    TokenString *str = macro_stack;
    macro_stack = str->prev;
    macro_ptr = str->prev_ptr;
    if (str->alloc == 2) {
        str->alloc = 3; /* just mark as finished */
    } else {
        tok_str_free(str->str);
        if (str->alloc == 1)
            tcc_free(str);
    }
}

ST_FUNC char *trimfront(char *p)
{
    while (*p && (unsigned char)*p <= ' ')
	++p;
    return p;
}

ST_FUNC char *trimback(char *a, char *e)
{
    while (e > a && (unsigned char)e[-1] <= ' ')
	--e;
    *e = 0;;
    return a;
}

/* ------------------------------------------------------------------------- */
/* Custom allocator for tiny objects */

ST_FUNC TinyAlloc *tal_new(TinyAlloc **pal, size_t limit, size_t size)
{
    TinyAlloc *al = tcc_mallocz(sizeof(TinyAlloc));
    al->p = al->buffer = tcc_malloc(size);
    al->limit = limit;
    al->size = size;
    if (pal) *pal = al;
    return al;
}

ST_FUNC void tal_delete(TinyAlloc *al)
{
    TinyAlloc *next;

tail_call:
    if (!al)
        return;
#ifdef TAL_INFO
    fprintf(stderr, "limit=%5d, size=%5g MB, nb_peak=%6d, nb_total=%8d, nb_missed=%6d, usage=%5.1f%%\n",
            al->limit, al->size / 1024.0 / 1024.0, al->nb_peak, al->nb_total, al->nb_missed,
            (al->peak_p - al->buffer) * 100.0 / al->size);
#endif
#ifdef TAL_DEBUG
    if (al->nb_allocs > 0) {
        fprintf(stderr, "TAL_DEBUG: mem leak %d chunks (limit= %d)\n",
                al->nb_allocs, al->limit);
        uint8_t *p = al->buffer;
        while (p < al->p) {
            tal_header_t *header = (tal_header_t *)p;
            if (header->line_num > 0) {
                fprintf(stderr, "  file %s, line %u: %u bytes\n",
                        header->file_name, header->line_num, header->size);
            }
            p += header->size + sizeof(tal_header_t);
        }
    }
#endif
    next = al->next;
    tcc_free(al->buffer);
    tcc_free(al);
    al = next;
    goto tail_call;
}

ST_FUNC void tal_free_impl(TinyAlloc *al, void *p TAL_DEBUG_PARAMS)
{
    if (!p)
        return;
tail_call:
    if (al->buffer <= (uint8_t *)p && (uint8_t *)p < al->buffer + al->size) {
#ifdef TAL_DEBUG
        tal_header_t *header = (((tal_header_t *)p) - 1);
        if (header->line_num < 0) {
            fprintf(stderr, "TAL_DEBUG: file %s, line %u double frees chunk from\n",
                    file, line);
            fprintf(stderr, "  file %s, line %u: %u bytes\n",
                    header->file_name, -header->line_num, header->size);
        } else
            header->line_num = -header->line_num;
#endif
        al->nb_allocs--;
        if (!al->nb_allocs)
            al->p = al->buffer;
    } else if (al->next) {
        al = al->next;
        goto tail_call;
    }
    else
        tcc_free(p);
}

ST_FUNC void *tal_realloc_impl(TinyAlloc **pal, void *p, size_t size TAL_DEBUG_PARAMS)
{
    tal_header_t *header;
    void *ret;
    int is_own;
    size_t adj_size = (size + 3) & -4;
    TinyAlloc *al = *pal;

tail_call:
    is_own = (al->buffer <= (uint8_t *)p && (uint8_t *)p < al->buffer + al->size);
    if ((!p || is_own) && size <= al->limit) {
        if (al->p + adj_size + sizeof(tal_header_t) < al->buffer + al->size) {
            header = (tal_header_t *)al->p;
            header->size = adj_size;
#ifdef TAL_DEBUG
            int ofs = strlen(file) - TAL_DEBUG_FILE_LEN;
            strncpy(header->file_name, file + (ofs > 0 ? ofs : 0), TAL_DEBUG_FILE_LEN);
            header->file_name[TAL_DEBUG_FILE_LEN] = 0;
            header->line_num = line;
#endif
            ret = al->p + sizeof(tal_header_t);
            al->p += adj_size + sizeof(tal_header_t);
            if (is_own) {
                header = (((tal_header_t *)p) - 1);
                memcpy(ret, p, header->size);
#ifdef TAL_DEBUG
                header->line_num = -header->line_num;
#endif
            } else {
                al->nb_allocs++;
            }
#ifdef TAL_INFO
            if (al->nb_peak < al->nb_allocs)
                al->nb_peak = al->nb_allocs;
            if (al->peak_p < al->p)
                al->peak_p = al->p;
            al->nb_total++;
#endif
            return ret;
        } else if (is_own) {
            al->nb_allocs--;
            ret = tal_realloc(*pal, 0, size);
            header = (((tal_header_t *)p) - 1);
            memcpy(ret, p, header->size);
#ifdef TAL_DEBUG
            header->line_num = -header->line_num;
#endif
            return ret;
        }
        if (al->next) {
            al = al->next;
        } else {
            TinyAlloc *bottom = al, *next = al->top ? al->top : al;

            al = tal_new(pal, next->limit, next->size * 2);
            al->next = next;
            bottom->top = al;
        }
        goto tail_call;
    }
    if (is_own) {
        al->nb_allocs--;
        ret = tcc_malloc(size);
        header = (((tal_header_t *)p) - 1);
        memcpy(ret, p, header->size);
#ifdef TAL_DEBUG
        header->line_num = -header->line_num;
#endif
    } else if (al->next) {
        al = al->next;
        goto tail_call;
    } else
        ret = tcc_realloc(p, size);
#ifdef TAL_INFO
    al->nb_missed++;
#endif
    return ret;
}

/* ------------------------------------------------------------------------- */
/* CString handling */
static void cstr_realloc(CString *cstr, int new_size)
{
    int size;
    void *data;

    size = cstr->size_allocated;
    if (size < 8)
        size = 8; /* no need to allocate a too small first string */
    while (size < new_size)
        size = size * 2;
    data = tal_realloc(cstr_alloc, cstr->data_allocated, size);
    cstr->data_allocated = data;
    cstr->size_allocated = size;
    cstr->data = data;
}

/* add a byte */
ST_FUNC void cstr_ccat(CString *cstr, int ch)
{
    int size;
    size = cstr->size + 1;
    if (size > cstr->size_allocated)
        cstr_realloc(cstr, size);
    ((unsigned char *)cstr->data)[size - 1] = ch;
    cstr->size = size;
}

ST_FUNC void cstr_cat(CString *cstr, const char *str, int len)
{
    int size;
    if (len <= 0)
        len = strlen(str) + 1 + len;
    size = cstr->size + len;
    if (size > cstr->size_allocated)
        cstr_realloc(cstr, size);
    memmove(((unsigned char *)cstr->data) + cstr->size, str, len);
    cstr->size = size;
}

/* add a wide char */
ST_FUNC void cstr_wccat(CString *cstr, int ch)
{
    int size;
    size = cstr->size + sizeof(nwchar_t);
    if (size > cstr->size_allocated)
        cstr_realloc(cstr, size);
    *(nwchar_t *)(((unsigned char *)cstr->data) + size - sizeof(nwchar_t)) = ch;
    cstr->size = size;
}

ST_FUNC void cstr_new(CString *cstr)
{
    memset(cstr, 0, sizeof(CString));
}

/* free string and reset it to NULL */
ST_FUNC void cstr_free(CString *cstr)
{
    tal_free(cstr_alloc, cstr->data_allocated);
    cstr_new(cstr);
}

/* reset string to empty */
ST_FUNC void cstr_reset(CString *cstr)
{
    cstr->size = 0;
}

/* XXX: unicode ? */
static void add_char(CString *cstr, int c)
{
    if (c == '\'' || c == '\"' || c == '\\') {
        /* XXX: could be more precise if char or string */
        cstr_ccat(cstr, '\\');
    }
    if (c >= 32 && c <= 126) {
        cstr_ccat(cstr, c);
    } else {
        cstr_ccat(cstr, '\\');
        if (c == '\n') {
            cstr_ccat(cstr, 'n');
        } else {
            cstr_ccat(cstr, '0' + ((c >> 6) & 7));
            cstr_ccat(cstr, '0' + ((c >> 3) & 7));
            cstr_ccat(cstr, '0' + (c & 7));
        }
    }
}

/* ------------------------------------------------------------------------- */
/* allocate a new token */
static TokenSym *tok_alloc_new(TokenSym **pts, const char *str, int len)
{
    TokenSym *ts, **ptable;
    int i;

    if (tok_ident >= SYM_FIRST_ANOM) 
        tcc_error("memory full (symbols)");

    /* expand token table if needed */
    i = tok_ident - TOK_IDENT;
    if ((i % TOK_ALLOC_INCR) == 0) {
        ptable = tcc_realloc(table_ident, (i + TOK_ALLOC_INCR) * sizeof(TokenSym *));
        table_ident = ptable;
    }

    ts = tal_realloc(toksym_alloc, 0, sizeof(TokenSym) + len);
    table_ident[i] = ts;
    ts->tok = tok_ident++;
    ts->sym_define = NULL;
    ts->sym_label = NULL;
    ts->sym_struct = NULL;
    ts->sym_identifier = NULL;
    ts->len = len;
    ts->hash_next = NULL;
    memcpy(ts->str, str, len);
    ts->str[len] = '\0';
    *pts = ts;
    return ts;
}

#define TOK_HASH_INIT 1
#define TOK_HASH_FUNC(h, c) ((h) + ((h) << 5) + ((h) >> 27) + (c))


/* find a token and add it if not found */
ST_FUNC TokenSym *tok_alloc(const char *str, int len)
{
    TokenSym *ts, **pts;
    int i;
    unsigned int h;
    
    h = TOK_HASH_INIT;
    for(i=0;i<len;i++)
        h = TOK_HASH_FUNC(h, ((unsigned char *)str)[i]);
    h &= (TOK_HASH_SIZE - 1);

    pts = &hash_ident[h];
    for(;;) {
        ts = *pts;
        if (!ts)
            break;
        if (ts->len == len && !memcmp(ts->str, str, len))
            return ts;
        pts = &(ts->hash_next);
    }
    return tok_alloc_new(pts, str, len);
}

/* XXX: buffer overflow */
/* XXX: float tokens */
ST_FUNC const char *get_tok_str(int v, CValue *cv)
{
    char *p;
    int i, len;

    cstr_reset(&cstr_buf);
    p = cstr_buf.data;

    switch(v) {
    case TOK_CINT:
    case TOK_CUINT:
    case TOK_CLLONG:
    case TOK_CULLONG:
        /* XXX: not quite exact, but only useful for testing  */
#ifdef _WIN32
        sprintf(p, "%u", (unsigned)cv->i);
#else
        sprintf(p, "%llu", (unsigned long long)cv->i);
#endif
        break;
    case TOK_LCHAR:
        cstr_ccat(&cstr_buf, 'L');
    case TOK_CCHAR:
        cstr_ccat(&cstr_buf, '\'');
        add_char(&cstr_buf, cv->i);
        cstr_ccat(&cstr_buf, '\'');
        cstr_ccat(&cstr_buf, '\0');
        break;
    case TOK_PPNUM:
    case TOK_PPSTR:
        return (char*)cv->str.data;
    case TOK_LSTR:
        cstr_ccat(&cstr_buf, 'L');
    case TOK_STR:
        cstr_ccat(&cstr_buf, '\"');
        if (v == TOK_STR) {
            len = cv->str.size - 1;
            for(i=0;i<len;i++)
                add_char(&cstr_buf, ((unsigned char *)cv->str.data)[i]);
        } else {
            len = (cv->str.size / sizeof(nwchar_t)) - 1;
            for(i=0;i<len;i++)
                add_char(&cstr_buf, ((nwchar_t *)cv->str.data)[i]);
        }
        cstr_ccat(&cstr_buf, '\"');
        cstr_ccat(&cstr_buf, '\0');
        break;

    case TOK_CFLOAT:
        cstr_cat(&cstr_buf, "<float>", 0);
        break;
    case TOK_CDOUBLE:
	cstr_cat(&cstr_buf, "<double>", 0);
	break;
    case TOK_CLDOUBLE:
	cstr_cat(&cstr_buf, "<long double>", 0);
	break;
    case TOK_LINENUM:
	cstr_cat(&cstr_buf, "<linenumber>", 0);
	break;

    /* above tokens have value, the ones below don't */

    case TOK_LT:
        v = '<';
        goto addv;
    case TOK_GT:
        v = '>';
        goto addv;
    case TOK_DOTS:
        return strcpy(p, "...");
    case TOK_A_SHL:
        return strcpy(p, "<<=");
    case TOK_A_SAR:
        return strcpy(p, ">>=");
    default:
        if (v < TOK_IDENT) {
            /* search in two bytes table */
            const unsigned char *q = tok_two_chars;
            while (*q) {
                if (q[2] == v) {
                    *p++ = q[0];
                    *p++ = q[1];
                    *p = '\0';
                    return cstr_buf.data;
                }
                q += 3;
            }
        if (v >= 127) {
            sprintf(cstr_buf.data, "<%02x>", v);
            return cstr_buf.data;
        }
        addv:
            *p++ = v;
            *p = '\0';
        } else if (v < tok_ident) {
            return table_ident[v - TOK_IDENT]->str;
        } else if (v >= SYM_FIRST_ANOM) {
            /* special name for anonymous symbol */
            sprintf(p, "L.%u", v - SYM_FIRST_ANOM);
        } else {
            /* should never happen */
            return NULL;
        }
        break;
    }
    return cstr_buf.data;
}

/* return the current character, handling end of block if necessary
   (but not stray) */
ST_FUNC int handle_eob(void)
{
    BufferedFile *bf = file;
    int len;

    /* only tries to read if really end of buffer */
    if (bf->buf_ptr >= bf->buf_end) {
        if (bf->fd != -1) {
#if defined(PARSE_DEBUG)
            len = 1;
#else
            len = IO_BUF_SIZE;
#endif
            len = tcc_io.read(bf->fd, bf->buffer, len);
            if (len < 0)
                len = 0;
        } else {
            len = 0;
        }
        total_bytes += len;
        bf->buf_ptr = bf->buffer;
        bf->buf_end = bf->buffer + len;
        *bf->buf_end = CH_EOB;
    }
    if (bf->buf_ptr < bf->buf_end) {
        return bf->buf_ptr[0];
    } else {
        bf->buf_ptr = bf->buf_end;
        return CH_EOF;
    }
}

/* read next char from current input file and handle end of input buffer */
ST_INLN void inp(void)
{
    ch = *(++(file->buf_ptr));
    /* end of buffer/file handling */
    if (ch == CH_EOB)
        ch = handle_eob();
}

/* handle '\[\r]\n' */
static int handle_stray_noerror(void)
{
    while (ch == '\\') {
        inp();
        if (ch == '\n') {
            file->line_num++;
            inp();
        } else if (ch == '\r') {
            inp();
            if (ch != '\n')
                goto fail;
            file->line_num++;
            inp();
        } else {
        fail:
            return 1;
        }
    }
    return 0;
}

static void handle_stray(void)
{
    if (handle_stray_noerror())
        tcc_error("stray '\\' in program");
}

/* skip the stray and handle the \\n case. Output an error if
   incorrect char after the stray */
static int handle_stray1(uint8_t *p)
{
    int c;

    file->buf_ptr = p;
    if (p >= file->buf_end) {
        c = handle_eob();
        if (c != '\\')
            return c;
        p = file->buf_ptr;
    }
    ch = *p;
    if (handle_stray_noerror()) {
        if (!(parse_flags & PARSE_FLAG_ACCEPT_STRAYS))
            tcc_error("stray '\\' in program");
        *--file->buf_ptr = '\\';
    }
    p = file->buf_ptr;
    c = *p;
    return c;
}

/* handle just the EOB case, but not stray */
#define PEEKC_EOB(c, p)\
{\
    p++;\
    c = *p;\
    if (c == '\\') {\
        file->buf_ptr = p;\
        c = handle_eob();\
        p = file->buf_ptr;\
    }\
}

/* handle the complicated stray case */
#define PEEKC(c, p)\
{\
    p++;\
    c = *p;\
    if (c == '\\') {\
        c = handle_stray1(p);\
        p = file->buf_ptr;\
    }\
}

/* input with '\[\r]\n' handling. Note that this function cannot
   handle other characters after '\', so you cannot call it inside
   strings or comments */
ST_FUNC void minp(void)
{
    inp();
    if (ch == '\\') 
        handle_stray();
}

/* single line C++ comments */
static uint8_t *parse_line_comment(uint8_t *p)
{
    int c;

    p++;
    for(;;) {
        c = *p;
    redo:
        if (c == '\n' || c == CH_EOF) {
            break;
        } else if (c == '\\') {
            file->buf_ptr = p;
            c = handle_eob();
            p = file->buf_ptr;
            if (c == '\\') {
                PEEKC_EOB(c, p);
                if (c == '\n') {
                    file->line_num++;
                    PEEKC_EOB(c, p);
                } else if (c == '\r') {
                    PEEKC_EOB(c, p);
                    if (c == '\n') {
                        file->line_num++;
                        PEEKC_EOB(c, p);
                    }
                }
            } else {
                goto redo;
            }
        } else {
            p++;
        }
    }
    return p;
}

/* C comments */
ST_FUNC uint8_t *parse_comment(uint8_t *p)
{
    int c;

    p++;
    for(;;) {
        /* fast skip loop */
        for(;;) {
            c = *p;
            if (c == '\n' || c == '*' || c == '\\')
                break;
            p++;
            c = *p;
            if (c == '\n' || c == '*' || c == '\\')
                break;
            p++;
        }
        /* now we can handle all the cases */
        if (c == '\n') {
            file->line_num++;
            p++;
        } else if (c == '*') {
            p++;
            for(;;) {
                c = *p;
                if (c == '*') {
                    p++;
                } else if (c == '/') {
                    goto end_of_comment;
                } else if (c == '\\') {
                    file->buf_ptr = p;
                    c = handle_eob();
                    p = file->buf_ptr;
                    if (c == CH_EOF)
                        tcc_error("unexpected end of file in comment");
                    if (c == '\\') {
                        /* skip '\[\r]\n', otherwise just skip the stray */
                        while (c == '\\') {
                            PEEKC_EOB(c, p);
                            if (c == '\n') {
                                file->line_num++;
                                PEEKC_EOB(c, p);
                            } else if (c == '\r') {
                                PEEKC_EOB(c, p);
                                if (c == '\n') {
                                    file->line_num++;
                                    PEEKC_EOB(c, p);
                                }
                            } else {
                                goto after_star;
                            }
                        }
                    }
                } else {
                    break;
                }
            }
        after_star: ;
        } else {
            /* stray, eob or eof */
            file->buf_ptr = p;
            c = handle_eob();
            p = file->buf_ptr;
            if (c == CH_EOF) {
                tcc_error("unexpected end of file in comment");
            } else if (c == '\\') {
                p++;
            }
        }
    }
 end_of_comment:
    p++;
    return p;
}

#define cinp minp

static inline void skip_spaces(void)
{
    while (isidnum_table[ch - CH_EOF] & IS_SPC)
        cinp();
}

static inline int check_space(int t, int *spc) 
{
    if (t < 256 && (isidnum_table[t - CH_EOF] & IS_SPC)) {
        if (*spc) 
            return 1;
        *spc = 1;
    } else 
        *spc = 0;
    return 0;
}

/* parse a string without interpreting escapes */
static uint8_t *parse_pp_string(uint8_t *p,
                                int sep, CString *str)
{
    int c;
    p++;
    for(;;) {
        c = *p;
        if (c == sep) {
            break;
        } else if (c == '\\') {
            file->buf_ptr = p;
            c = handle_eob();
            p = file->buf_ptr;
            if (c == CH_EOF) {
            unterminated_string:
                /* XXX: indicate line number of start of string */
                tcc_error("missing terminating %c character", sep);
            } else if (c == '\\') {
                /* escape : just skip \[\r]\n */
                PEEKC_EOB(c, p);
                if (c == '\n') {
                    file->line_num++;
                    p++;
                } else if (c == '\r') {
                    PEEKC_EOB(c, p);
                    if (c != '\n')
                        expect("'\n' after '\r'");
                    file->line_num++;
                    p++;
                } else if (c == CH_EOF) {
                    goto unterminated_string;
                } else {
                    if (str) {
                        cstr_ccat(str, '\\');
                        cstr_ccat(str, c);
                    }
                    p++;
                }
            }
        } else if (c == '\n') {
            file->line_num++;
            goto add_char;
        } else if (c == '\r') {
            PEEKC_EOB(c, p);
            if (c != '\n') {
                if (str)
                    cstr_ccat(str, '\r');
            } else {
                file->line_num++;
                goto add_char;
            }
        } else {
        add_char:
            if (str)
                cstr_ccat(str, c);
            p++;
        }
    }
    p++;
    return p;
}

/* skip block of text until #else, #elif or #endif. skip also pairs of
   #if/#endif */
static void preprocess_skip(void)
{
    int a, start_of_line, c, in_warn_or_error;
    uint8_t *p;

    p = file->buf_ptr;
    a = 0;
redo_start:
    start_of_line = 1;
    in_warn_or_error = 0;
    for(;;) {
    redo_no_start:
        c = *p;
        switch(c) {
        case ' ':
        case '\t':
        case '\f':
        case '\v':
        case '\r':
            p++;
            goto redo_no_start;
        case '\n':
            file->line_num++;
            p++;
            goto redo_start;
        case '\\':
            file->buf_ptr = p;
            c = handle_eob();
            if (c == CH_EOF) {
                expect("#endif");
            } else if (c == '\\') {
                ch = file->buf_ptr[0];
                handle_stray_noerror();
            }
            p = file->buf_ptr;
            goto redo_no_start;
        /* skip strings */
        case '\"':
        case '\'':
            if (in_warn_or_error)
                goto _default;
            p = parse_pp_string(p, c, NULL);
            break;
        /* skip comments */
        case '/':
            if (in_warn_or_error)
                goto _default;
            file->buf_ptr = p;
            ch = *p;
            minp();
            p = file->buf_ptr;
            if (ch == '*') {
                p = parse_comment(p);
            } else if (ch == '/') {
                p = parse_line_comment(p);
            }
            break;
        case '#':
            p++;
            if (start_of_line) {
                file->buf_ptr = p;
                next_nomacro();
                p = file->buf_ptr;
                if (a == 0 && 
                    (tok == TOK_ELSE || tok == TOK_ELIF || tok == TOK_ENDIF))
                    goto the_end;
                if (tok == TOK_IF || tok == TOK_IFDEF || tok == TOK_IFNDEF)
                    a++;
                else if (tok == TOK_ENDIF)
                    a--;
                else if( tok == TOK_ERROR || tok == TOK_WARNING)
                    in_warn_or_error = 1;
                else if (tok == TOK_LINEFEED)
                    goto redo_start;
                else if (parse_flags & PARSE_FLAG_ASM_FILE)
                    p = parse_line_comment(p);
            } else if (parse_flags & PARSE_FLAG_ASM_FILE)
                p = parse_line_comment(p);
            break;
_default:
        default:
            p++;
            break;
        }
        start_of_line = 0;
    }
 the_end: ;
    file->buf_ptr = p;
}

/* ParseState handling */

/* XXX: currently, no include file info is stored. Thus, we cannot display
   accurate messages if the function or data definition spans multiple
   files */

/* save current parse state in 's' */
ST_FUNC void save_parse_state(ParseState *s)
{
    s->line_num = file->line_num;
    s->macro_ptr = macro_ptr;
    s->tok = tok;
    s->tokc = tokc;
}

/* restore parse state from 's' */
ST_FUNC void restore_parse_state(ParseState *s)
{
    file->line_num = s->line_num;
    macro_ptr = s->macro_ptr;
    tok = s->tok;
    tokc = s->tokc;
}

/* return the number of additional 'ints' necessary to store the
   token */
static inline int tok_size(const int *p)
{
    switch(*p) {
        /* 4 bytes */
    case TOK_CINT:
    case TOK_CUINT:
    case TOK_CCHAR:
    case TOK_LCHAR:
    case TOK_CFLOAT:
    case TOK_LINENUM:
        return 1 + 1;
    case TOK_STR:
    case TOK_LSTR:
    case TOK_PPNUM:
    case TOK_PPSTR:
        return 1 + ((sizeof(CString) + ((CString *)(p+1))->size + 3) >> 2);
    case TOK_CDOUBLE:
    case TOK_CLLONG:
    case TOK_CULLONG:
        return 1 + 2;
    case TOK_CLDOUBLE:
        return 1 + LDOUBLE_SIZE / 4;
    default:
        return 1 + 0;
    }
}

/* token string handling */

ST_INLN void tok_str_new(TokenString *s)
{
    s->str = NULL;
    s->len = 0;
    s->allocated_len = 0;
    s->last_line_num = -1;
}

ST_FUNC int *tok_str_dup(TokenString *s)
{
    int *str;

    str = tal_realloc(tokstr_alloc, 0, s->len * sizeof(int));
    memcpy(str, s->str, s->len * sizeof(int));
    return str;
}

ST_FUNC void tok_str_free(int *str)
{
    tal_free(tokstr_alloc, str);
}

ST_FUNC int *tok_str_realloc(TokenString *s, int new_size)
{
    int *str, size;

    size = s->allocated_len;
    if (size < 16)
        size = 16;
    while (size < new_size)
        size = size * 2;
    TCC_ASSERT((size & (size -1)) == 0);
    if (size > s->allocated_len) {
        str = tal_realloc(tokstr_alloc, s->str, size * sizeof(int));
        s->allocated_len = size;
        s->str = str;
    }
    return s->str;
}

ST_FUNC void tok_str_add(TokenString *s, int t)
{
    int len, *str;

    len = s->len;
    str = s->str;
    if (len >= s->allocated_len)
        str = tok_str_realloc(s, len + 1);
    str[len++] = t;
    s->len = len;
}

static void tok_str_add2(TokenString *s, int t, CValue *cv)
{
    int len, *str;

    len = s->len;
    str = s->str;

    /* allocate space for worst case */
    if (len + TOK_MAX_SIZE >= s->allocated_len)
        str = tok_str_realloc(s, len + TOK_MAX_SIZE + 1);
    str[len++] = t;
    switch(t) {
    case TOK_CINT:
    case TOK_CUINT:
    case TOK_CCHAR:
    case TOK_LCHAR:
    case TOK_CFLOAT:
    case TOK_LINENUM:
        str[len++] = cv->tab[0];
        break;
    case TOK_PPNUM:
    case TOK_PPSTR:
    case TOK_STR:
    case TOK_LSTR:
        {
            /* Insert the string into the int array. */
            size_t nb_words =
                1 + (cv->str.size + sizeof(int) - 1) / sizeof(int);
            if (len + nb_words >= s->allocated_len)
                str = tok_str_realloc(s, len + nb_words + 1);
            str[len] = cv->str.size;
            memcpy(&str[len + 1], cv->str.data, cv->str.size);
            len += nb_words;
        }
        break;
    case TOK_CDOUBLE:
    case TOK_CLLONG:
    case TOK_CULLONG:
#if LDOUBLE_SIZE == 8
    case TOK_CLDOUBLE:
#endif
        str[len++] = cv->tab[0];
        str[len++] = cv->tab[1];
        break;
#if LDOUBLE_SIZE == 12
    case TOK_CLDOUBLE:
        str[len++] = cv->tab[0];
        str[len++] = cv->tab[1];
        str[len++] = cv->tab[2];
#elif LDOUBLE_SIZE == 16
    case TOK_CLDOUBLE:
        str[len++] = cv->tab[0];
        str[len++] = cv->tab[1];
        str[len++] = cv->tab[2];
        str[len++] = cv->tab[3];
#elif LDOUBLE_SIZE != 8
#error add long double size support
#endif
        break;
    default:
        break;
    }
    s->len = len;
}

/* add the current parse token in token string 's' */
ST_FUNC void tok_str_add_tok(TokenString *s)
{
    CValue cval;

    /* save line number info */
    if (file->line_num != s->last_line_num) {
        s->last_line_num = file->line_num;
        cval.i = s->last_line_num;
        tok_str_add2(s, TOK_LINENUM, &cval);
    }
    tok_str_add2(s, tok, &tokc);
}

/* get a token from an integer array and increment pointer
   accordingly. we code it as a macro to avoid pointer aliasing. */
static inline void TOK_GET(int *t, const int **pp, CValue *cv)
{
    const int *p = *pp;
    int n, *tab;

    tab = cv->tab;
    switch(*t = *p++) {
    case TOK_CINT:
    case TOK_CUINT:
    case TOK_CCHAR:
    case TOK_LCHAR:
    case TOK_CFLOAT:
    case TOK_LINENUM:
        tab[0] = *p++;
        break;
    case TOK_STR:
    case TOK_LSTR:
    case TOK_PPNUM:
    case TOK_PPSTR:
        cv->str.size = *p++;
        cv->str.data = p;
        cv->str.data_allocated = 0;
        p += (cv->str.size + sizeof(int) - 1) / sizeof(int);
        break;
    case TOK_CDOUBLE:
    case TOK_CLLONG:
    case TOK_CULLONG:
        n = 2;
        goto copy;
    case TOK_CLDOUBLE:
#if LDOUBLE_SIZE == 16
        n = 4;
#elif LDOUBLE_SIZE == 12
        n = 3;
#elif LDOUBLE_SIZE == 8
        n = 2;
#else
# error add long double size support
#endif
    copy:
        do
            *tab++ = *p++;
        while (--n);
        break;
    default:
        break;
    }
    *pp = p;
}

/* Calling this function is expensive, but it is not possible
   to read a token string backwards. */
static int tok_last(const int *str0, const int *str1)
{
    const int *str = str0;
    int tok = 0;
    CValue cval;

    while (str < str1)
        TOK_GET(&tok, &str, &cval);
    return tok;
}

static int macro_is_equal(const int *a, const int *b)
{
    CValue cv;
    int t;

    if (!a || !b)
        return 1;

    while (*a && *b) {
        /* first time preallocate static cstr_buf, next time only reset position to start */
        cstr_reset(&cstr_buf);
        TOK_GET(&t, &a, &cv);
        cstr_cat(&cstr_buf, get_tok_str(t, &cv), 0);
        TOK_GET(&t, &b, &cv);
        if (strcmp(cstr_buf.data, get_tok_str(t, &cv)))
            return 0;
    }
    return !(*a || *b);
}

/* defines handling */
ST_INLN void define_push(int v, int macro_type, TokenString *str, Sym *first_arg)
{
    Sym *s, *o;

    o = define_find(v);
    s = sym_push2(&define_stack, v, macro_type, 0);
    s->d = str ? tok_str_dup(str) : NULL;
    s->next = first_arg;
    table_ident[v - TOK_IDENT]->sym_define = s;

    if (o && !macro_is_equal(o->d, s->d))
	tcc_warning("%s redefined", get_tok_str(v, NULL));
}

/* undefined a define symbol. Its name is just set to zero */
ST_FUNC void define_undef(Sym *s)
{
    int v = s->v;
    if (v >= TOK_IDENT && v < tok_ident)
        table_ident[v - TOK_IDENT]->sym_define = NULL;
}

ST_INLN Sym *define_find(int v)
{
    v -= TOK_IDENT;
    if ((unsigned)v >= (unsigned)(tok_ident - TOK_IDENT))
        return NULL;
    return table_ident[v]->sym_define;
}

/* free define stack until top reaches 'b' */
ST_FUNC void free_defines(Sym *b)
{
    Sym *top, *top1;
    int v;

    top = define_stack;
    while (top != b) {
        top1 = top->prev;
        /* do not free args or predefined defines */
        if (top->d)
            tok_str_free(top->d);
        v = top->v;
        if (v >= TOK_IDENT && v < tok_ident)
            table_ident[v - TOK_IDENT]->sym_define = NULL;
        sym_free(top);
        top = top1;
    }
    define_stack = b;
}

/* label lookup */
ST_FUNC Sym *label_find(int v)
{
    v -= TOK_IDENT;
    if ((unsigned)v >= (unsigned)(tok_ident - TOK_IDENT))
        return NULL;
    return table_ident[v]->sym_label;
}

ST_FUNC Sym *label_push(Sym **ptop, int v, int flags)
{
    Sym *s, **ps;
    s = sym_push2(ptop, v, 0, 0);
    s->r = flags;
    ps = &table_ident[v - TOK_IDENT]->sym_label;
    if (ptop == &global_label_stack) {
        /* modify the top most local identifier, so that
           sym_identifier will point to 's' when popped */
        while (*ps != NULL)
            ps = &(*ps)->prev_tok;
    }
    s->prev_tok = *ps;
    *ps = s;
    return s;
}

/* pop labels until element last is reached. Look if any labels are
   undefined. Define symbols if '&&label' was used. */
ST_FUNC void label_pop(Sym **ptop, Sym *slast)
{
    Sym *s, *s1;
    for(s = *ptop; s != slast; s = s1) {
        s1 = s->prev;
        if (s->r == LABEL_DECLARED) {
            tcc_warning("label '%s' declared but not used", get_tok_str(s->v, NULL));
        } else if (s->r == LABEL_FORWARD) {
                tcc_error("label '%s' used but not defined",
                      get_tok_str(s->v, NULL));
        } else {
            if (s->c) {
                /* define corresponding symbol. A size of
                   1 is put. */
                put_extern_sym(s, cur_text_section, s->jnext, 1);
            }
        }
        /* remove label */
        table_ident[s->v - TOK_IDENT]->sym_label = s->prev_tok;
        sym_free(s);
    }
    *ptop = slast;
}

/* eval an expression for #if/#elif */
static int expr_preprocess(void)
{
    int c, t;
    TokenString str;
    
    tok_str_new(&str);
    while (tok != TOK_LINEFEED && tok != TOK_EOF) {
        next(); /* do macro subst */
        if (tok == TOK_DEFINED) {
            next_nomacro();
            t = tok;
            if (t == '(') 
                next_nomacro();
            c = define_find(tok) != 0;
            if (t == '(')
                next_nomacro();
            tok = TOK_CINT;
            tokc.i = c;
        } else if (tok >= TOK_IDENT) {
            /* if undefined macro */
            tok = TOK_CINT;
            tokc.i = 0;
        }
        tok_str_add_tok(&str);
    }
    tok_str_add(&str, -1); /* simulate end of file */
    tok_str_add(&str, 0);
    /* now evaluate C constant expression */
    begin_macro(&str, 0);
    next();
    c = expr_const();
    end_macro();
    return c != 0;
}


/* parse after #define */
ST_FUNC void parse_define(void)
{
    Sym *s, *first, **ps;
    int v, t, varg, is_vaargs, spc;
    int saved_parse_flags = parse_flags;

    v = tok;
    if (v < TOK_IDENT)
        tcc_error("invalid macro name '%s'", get_tok_str(tok, &tokc));
    /* XXX: should check if same macro (ANSI) */
    first = NULL;
    t = MACRO_OBJ;
    /* '(' must be just after macro definition for MACRO_FUNC */
    parse_flags |= PARSE_FLAG_SPACES;
    next_nomacro_spc();
    if (tok == '(') {
        /* must be able to parse TOK_DOTS (in asm mode '.' can be part of identifier) */
        parse_flags &= ~PARSE_FLAG_ASM_FILE;
        isidnum_table['.' - CH_EOF] = 0;
        next_nomacro();
        ps = &first;
        if (tok != ')') for (;;) {
            varg = tok;
            next_nomacro();
            is_vaargs = 0;
            if (varg == TOK_DOTS) {
                varg = TOK___VA_ARGS__;
                is_vaargs = 1;
            } else if (tok == TOK_DOTS && gnu_ext) {
                is_vaargs = 1;
                next_nomacro();
            }
            if (varg < TOK_IDENT)
        bad_list:
                tcc_error("bad macro parameter list");
            s = sym_push2(&define_stack, varg | SYM_FIELD, is_vaargs, 0);
            *ps = s;
            ps = &s->next;
            if (tok == ')')
                break;
            if (tok != ',' || is_vaargs)
                goto bad_list;
            next_nomacro();
        }
        next_nomacro_spc();
        t = MACRO_FUNC;
        parse_flags |= (saved_parse_flags & PARSE_FLAG_ASM_FILE);
        isidnum_table['.' - CH_EOF] =
            (parse_flags & PARSE_FLAG_ASM_FILE) ? IS_ID : 0;
    }

    tokstr_buf.len = 0;
    spc = 2;
    parse_flags |= PARSE_FLAG_ACCEPT_STRAYS | PARSE_FLAG_SPACES | PARSE_FLAG_LINEFEED;
    while (tok != TOK_LINEFEED && tok != TOK_EOF) {
        /* remove spaces around ## and after '#' */
        if (TOK_TWOSHARPS == tok) {
            if (2 == spc)
                goto bad_twosharp;
            if (1 == spc)
                --tokstr_buf.len;
            spc = 3;
        } else if ('#' == tok) {
            spc = 4;
        } else if (check_space(tok, &spc)) {
            goto skip;
        }
        tok_str_add2(&tokstr_buf, tok, &tokc);
    skip:
        next_nomacro_spc();
    }

    parse_flags = saved_parse_flags;
    if (spc == 1)
        --tokstr_buf.len; /* remove trailing space */
    tok_str_add(&tokstr_buf, 0);
    if (3 == spc)
bad_twosharp:
        tcc_error("'##' cannot appear at either end of macro");
    define_push(v, t, &tokstr_buf, first);
}

static inline int hash_cached_include(const char *filename)
{
    const unsigned char *s;
    unsigned int h;

    h = TOK_HASH_INIT;
    s = (unsigned char *) filename;
    while (*s) {
        h = TOK_HASH_FUNC(h, *s);
        s++;
    }
    h &= (CACHED_INCLUDES_HASH_SIZE - 1);
    return h;
}

static CachedInclude *search_cached_include(TCCState *s1, const char *filename)
{
    CachedInclude *e;
    int i, h;
    h = hash_cached_include(filename);
    i = s1->cached_includes_hash[h];
    for(;;) {
        if (i == 0)
            break;
        e = s1->cached_includes[i - 1];
        if (0 == PATHCMP(e->filename, filename))
            return e;
        i = e->hash_next;
    }
    return NULL;
}

static inline void add_cached_include(TCCState *s1, const char *filename, int ifndef_macro)
{
    CachedInclude *e;
    int h;

    if (search_cached_include(s1, filename))
        return;
#ifdef INC_DEBUG
    printf("adding cached '%s' %s\n", filename, get_tok_str(ifndef_macro, NULL));
#endif
    e = tcc_malloc(sizeof(CachedInclude) + strlen(filename));
    strcpy(e->filename, filename);
    e->ifndef_macro = ifndef_macro;
    dynarray_add((void ***)&s1->cached_includes, &s1->nb_cached_includes, e);
    /* add in hash table */
    h = hash_cached_include(filename);
    e->hash_next = s1->cached_includes_hash[h];
    s1->cached_includes_hash[h] = s1->nb_cached_includes;
}

#define ONCE_PREFIX "#ONCE#"

static void pragma_parse(TCCState *s1)
{
    next_nomacro();
    if (tok == TOK_push_macro || tok == TOK_pop_macro) {
        int t = tok, v;
        Sym *s;

        if (next(), tok != '(')
            goto pragma_err;
        if (next(), tok != TOK_STR)
            goto pragma_err;
        v = tok_alloc(tokc.str.data, tokc.str.size - 1)->tok;
        if (next(), tok != ')')
            goto pragma_err;
        if (t == TOK_push_macro) {
            while (NULL == (s = define_find(v)))
                define_push(v, 0, NULL, NULL);
            s->type.ref = s; /* set push boundary */
        } else {
            for (s = define_stack; s; s = s->prev)
                if (s->v == v && s->type.ref == s) {
                    s->type.ref = NULL;
                    break;
                }
        }
        if (s)
            table_ident[v - TOK_IDENT]->sym_define = s->d ? s : NULL;
        else
            tcc_warning("unbalanced #pragma pop_macro");
        pp_debug_tok = t, pp_debug_symv = v;

    } else if (tok == TOK_once) {
        char buf1[sizeof(file->filename) + sizeof(ONCE_PREFIX)];
        strcpy(buf1, ONCE_PREFIX);
        strcat(buf1, file->filename);
#ifdef PATH_NOCASE
        strupr(buf1);
#endif
        add_cached_include(s1, file->filename, tok_alloc(buf1, strlen(buf1))->tok);
    } else if (s1->ppfp) {
        /* tcc -E: keep pragmas below unchanged */
        unget_tok(' ');
        unget_tok(TOK_PRAGMA);
        unget_tok('#');
        unget_tok(TOK_LINEFEED);

    } else if (tok == TOK_pack) {
        /* This may be:
           #pragma pack(1) // set
           #pragma pack() // reset to default
           #pragma pack(push,1) // push & set
           #pragma pack(pop) // restore previous */
        next();
        skip('(');
        if (tok == TOK_ASM_pop) {
            next();
            if (s1->pack_stack_ptr <= s1->pack_stack) {
            stk_error:
                tcc_error("out of pack stack");
            }
            s1->pack_stack_ptr--;
        } else {
            int val = 0;
            if (tok != ')') {
                if (tok == TOK_ASM_push) {
                    next();
                    if (s1->pack_stack_ptr >= s1->pack_stack + PACK_STACK_SIZE - 1)
                        goto stk_error;
                    s1->pack_stack_ptr++;
                    skip(',');
                }
                if (tok != TOK_CINT)
                    goto pragma_err;
                val = tokc.i;
                if (val < 1 || val > 16 || (val & (val - 1)) != 0)
                    goto pragma_err;
                next();
            }
            *s1->pack_stack_ptr = val;
        }
        if (tok != ')')
            goto pragma_err;

    } else if (tok == TOK_comment) {
        char *file;
        next();
        skip('(');
        if (tok != TOK_lib)
            goto pragma_warn;
        next();
        skip(',');
        if (tok != TOK_STR)
            goto pragma_err;
        file = tcc_strdup((char *)tokc.str.data);
        dynarray_add((void ***)&s1->pragma_libs, &s1->nb_pragma_libs, file);
        next();
        if (tok != ')')
            goto pragma_err;
    } else {
pragma_warn:
        if (s1->warn_unsupported)
            tcc_warning("#pragma %s is ignored", get_tok_str(tok, &tokc));
    }
    return;

pragma_err:
    tcc_error("malformed #pragma directive");
    return;
}

/* is_bof is true if first non space token at beginning of file */
ST_FUNC void preprocess(int is_bof)
{
    TCCState *s1 = tcc_state;
    int i, c, n, saved_parse_flags;
    char buf[1024], *q;
    Sym *s;

    saved_parse_flags = parse_flags;
    parse_flags = PARSE_FLAG_PREPROCESS
        | PARSE_FLAG_TOK_NUM
        | PARSE_FLAG_TOK_STR
        | PARSE_FLAG_LINEFEED
        | (parse_flags & PARSE_FLAG_ASM_FILE)
        ;

    next_nomacro();
 redo:
    switch(tok) {
    case TOK_DEFINE:
        pp_debug_tok = tok;
        next_nomacro();
        pp_debug_symv = tok;
        parse_define();
        break;
    case TOK_UNDEF:
        pp_debug_tok = tok;
        next_nomacro();
        pp_debug_symv = tok;
        s = define_find(tok);
        /* undefine symbol by putting an invalid name */
        if (s)
            define_undef(s);
        break;
    case TOK_INCLUDE:
    case TOK_INCLUDE_NEXT:
        ch = file->buf_ptr[0];
        /* XXX: incorrect if comments : use next_nomacro with a special mode */
        skip_spaces();
        if (ch == '<') {
            c = '>';
            goto read_name;
        } else if (ch == '\"') {
            c = ch;
        read_name:
            inp();
            q = buf;
            while (ch != c && ch != '\n' && ch != CH_EOF) {
                if ((q - buf) < sizeof(buf) - 1)
                    *q++ = ch;
                if (ch == '\\') {
                    if (handle_stray_noerror() == 0)
                        --q;
                } else
                    inp();
            }
            *q = '\0';
            minp();
#if 0
            /* eat all spaces and comments after include */
            /* XXX: slightly incorrect */
            while (ch1 != '\n' && ch1 != CH_EOF)
                inp();
#endif
        } else {
            /* computed #include : either we have only strings or
               we have anything enclosed in '<>' */
            next();
            buf[0] = '\0';
            if (tok == TOK_STR) {
                while (tok != TOK_LINEFEED) {
                    if (tok != TOK_STR) {
                    include_syntax:
                        tcc_error("'#include' expects \"FILENAME\" or <FILENAME>");
                    }
                    pstrcat(buf, sizeof(buf), (char *)tokc.str.data);
                    next();
                }
                c = '\"';
            } else {
                int len;
                while (tok != TOK_LINEFEED) {
                    pstrcat(buf, sizeof(buf), get_tok_str(tok, &tokc));
                    next();
                }
                len = strlen(buf);
                /* check syntax and remove '<>' */
                if (len < 2 || buf[0] != '<' || buf[len - 1] != '>')
                    goto include_syntax;
                memmove(buf, buf + 1, len - 2);
                buf[len - 2] = '\0';
                c = '>';
            }
        }

        if (s1->include_stack_ptr >= s1->include_stack + INCLUDE_STACK_SIZE)
            tcc_error("#include recursion too deep");
        /* store current file in stack, but increment stack later below */
        *s1->include_stack_ptr = file;
        i = tok == TOK_INCLUDE_NEXT ? file->include_next_index : 0;
        n = 2 + s1->nb_include_paths + s1->nb_sysinclude_paths;
        for (; i < n; ++i) {
            char buf1[sizeof file->filename];
            CachedInclude *e;
            const char *path;

            if (i == 0) {
                /* check absolute include path */
                if (!IS_ABSPATH(buf))
                    continue;
                buf1[0] = 0;

            } else if (i == 1) {
                /* search in current dir if "header.h" */
                if (c != '\"')
                    continue;
                path = file->filename;
                pstrncpy(buf1, path, tcc_basename(path) - path);

            } else {
                /* search in all the include paths */
                int j = i - 2, k = j - s1->nb_include_paths;
                path = k < 0 ? s1->include_paths[j] : s1->sysinclude_paths[k];
                if (path == 0) continue;
                pstrcpy(buf1, sizeof(buf1), path);
                pstrcat(buf1, sizeof(buf1), "/");
            }

            pstrcat(buf1, sizeof(buf1), buf);
            e = search_cached_include(s1, buf1);
            if (e && define_find(e->ifndef_macro)) {
                /* no need to parse the include because the 'ifndef macro'
                   is defined */
#ifdef INC_DEBUG
                printf("%s: skipping cached %s\n", file->filename, buf1);
#endif
                goto include_done;
            }

            if (tcc_open(s1, buf1) < 0)
                continue;

            file->include_next_index = i + 1;
#ifdef INC_DEBUG
            printf("%s: including %s\n", file->prev->filename, file->filename);
#endif
            /* update target deps */
            dynarray_add((void ***)&s1->target_deps, &s1->nb_target_deps,
                    tcc_strdup(buf1));
            /* push current file in stack */
            ++s1->include_stack_ptr;
            /* add include file debug info */
            if (s1->do_debug)
                put_stabs(file->filename, N_BINCL, 0, 0, 0);
            tok_flags |= TOK_FLAG_BOF | TOK_FLAG_BOL;
            ch = file->buf_ptr[0];
            goto the_end;
        }
        tcc_error("include file '%s' not found", buf);
include_done:
        break;
    case TOK_IFNDEF:
        c = 1;
        goto do_ifdef;
    case TOK_IF:
        c = expr_preprocess();
        goto do_if;
    case TOK_IFDEF:
        c = 0;
    do_ifdef:
        next_nomacro();
        if (tok < TOK_IDENT)
            tcc_error("invalid argument for '#if%sdef'", c ? "n" : "");
        if (is_bof) {
            if (c) {
#ifdef INC_DEBUG
                printf("#ifndef %s\n", get_tok_str(tok, NULL));
#endif
                file->ifndef_macro = tok;
            }
        }
        c = (define_find(tok) != 0) ^ c;
    do_if:
        if (s1->ifdef_stack_ptr >= s1->ifdef_stack + IFDEF_STACK_SIZE)
            tcc_error("memory full (ifdef)");
        *s1->ifdef_stack_ptr++ = c;
        goto test_skip;
    case TOK_ELSE:
        if (s1->ifdef_stack_ptr == s1->ifdef_stack)
            tcc_error("#else without matching #if");
        if (s1->ifdef_stack_ptr[-1] & 2)
            tcc_error("#else after #else");
        c = (s1->ifdef_stack_ptr[-1] ^= 3);
        goto test_else;
    case TOK_ELIF:
        if (s1->ifdef_stack_ptr == s1->ifdef_stack)
            tcc_error("#elif without matching #if");
        c = s1->ifdef_stack_ptr[-1];
        if (c > 1)
            tcc_error("#elif after #else");
        /* last #if/#elif expression was true: we skip */
        if (c == 1)
            goto skip;
        c = expr_preprocess();
        s1->ifdef_stack_ptr[-1] = c;
    test_else:
        if (s1->ifdef_stack_ptr == file->ifdef_stack_ptr + 1)
            file->ifndef_macro = 0;
    test_skip:
        if (!(c & 1)) {
        skip:
            preprocess_skip();
            is_bof = 0;
            goto redo;
        }
        break;
    case TOK_ENDIF:
        if (s1->ifdef_stack_ptr <= file->ifdef_stack_ptr)
            tcc_error("#endif without matching #if");
        s1->ifdef_stack_ptr--;
        /* '#ifndef macro' was at the start of file. Now we check if
           an '#endif' is exactly at the end of file */
        if (file->ifndef_macro &&
            s1->ifdef_stack_ptr == file->ifdef_stack_ptr) {
            file->ifndef_macro_saved = file->ifndef_macro;
            /* need to set to zero to avoid false matches if another
               #ifndef at middle of file */
            file->ifndef_macro = 0;
            while (tok != TOK_LINEFEED)
                next_nomacro();
            tok_flags |= TOK_FLAG_ENDIF;
            goto the_end;
        }
        break;
    case TOK_PPNUM:
        n = strtoul((char*)tokc.str.data, &q, 10);
        goto _line_num;
    case TOK_LINE:
        next();
        if (tok != TOK_CINT)
_line_err:
            tcc_error("wrong #line format");
        n = tokc.i;
_line_num:
        next();
        if (tok != TOK_LINEFEED) {
            if (tok == TOK_STR)
                pstrcpy(file->filename, sizeof(file->filename), (char *)tokc.str.data);
            else if (parse_flags & PARSE_FLAG_ASM_FILE)
                break;
            else
                goto _line_err;
            --n;
        }
        if (file->fd > 0)
            total_lines += file->line_num - n;
        file->line_num = n;
        if (s1->do_debug)
    	    put_stabs(file->filename, N_BINCL, 0, 0, 0);
        break;
    case TOK_ERROR:
    case TOK_WARNING:
        c = tok;
        ch = file->buf_ptr[0];
        skip_spaces();
        q = buf;
        while (ch != '\n' && ch != CH_EOF) {
            if ((q - buf) < sizeof(buf) - 1)
                *q++ = ch;
            if (ch == '\\') {
                if (handle_stray_noerror() == 0)
                    --q;
            } else
                inp();
        }
        *q = '\0';
        if (c == TOK_ERROR)
            tcc_error("#error %s", buf);
        else
            tcc_warning("#warning %s", buf);
        break;
    case TOK_PRAGMA:
        pragma_parse(s1);
        break;
    case TOK_LINEFEED:
        goto the_end;
    default:
        /* ignore gas line comment in an 'S' file. */
        if (saved_parse_flags & PARSE_FLAG_ASM_FILE)
            goto ignore;
        if (tok == '!' && is_bof)
            /* '!' is ignored at beginning to allow C scripts. */
            goto ignore;
        tcc_warning("Ignoring unknown preprocessing directive #%s", get_tok_str(tok, &tokc));
    ignore:
        file->buf_ptr = parse_line_comment(file->buf_ptr);
        goto the_end;
    }
    /* ignore other preprocess commands or #! for C scripts */
    while (tok != TOK_LINEFEED)
        next_nomacro();
 the_end:
    parse_flags = saved_parse_flags;
}

/* evaluate escape codes in a string. */
static void parse_escape_string(CString *outstr, const uint8_t *buf, int is_long)
{
    int c, n;
    const uint8_t *p;

    p = buf;
    for(;;) {
        c = *p;
        if (c == '\0')
            break;
        if (c == '\\') {
            p++;
            /* escape */
            c = *p;
            switch(c) {
            case '0': case '1': case '2': case '3':
            case '4': case '5': case '6': case '7':
                /* at most three octal digits */
                n = c - '0';
                p++;
                c = *p;
                if (isoct(c)) {
                    n = n * 8 + c - '0';
                    p++;
                    c = *p;
                    if (isoct(c)) {
                        n = n * 8 + c - '0';
                        p++;
                    }
                }
                c = n;
                goto add_char_nonext;
            case 'x':
            case 'u':
            case 'U':
                p++;
                n = 0;
                for(;;) {
                    c = *p;
                    if (c >= 'a' && c <= 'f')
                        c = c - 'a' + 10;
                    else if (c >= 'A' && c <= 'F')
                        c = c - 'A' + 10;
                    else if (isnum(c))
                        c = c - '0';
                    else
                        break;
                    n = n * 16 + c;
                    p++;
                }
                c = n;
                goto add_char_nonext;
            case 'a':
                c = '\a';
                break;
            case 'b':
                c = '\b';
                break;
            case 'f':
                c = '\f';
                break;
            case 'n':
                c = '\n';
                break;
            case 'r':
                c = '\r';
                break;
            case 't':
                c = '\t';
                break;
            case 'v':
                c = '\v';
                break;
            case 'e':
                if (!gnu_ext)
                    goto invalid_escape;
                c = 27;
                break;
            case '\'':
            case '\"':
            case '\\': 
            case '?':
                break;
            default:
            invalid_escape:
                if (c >= '!' && c <= '~')
                    tcc_warning("unknown escape sequence: \'\\%c\'", c);
                else
                    tcc_warning("unknown escape sequence: \'\\x%x\'", c);
                break;
            }
        }
        p++;
    add_char_nonext:
        if (!is_long)
            cstr_ccat(outstr, c);
        else
            cstr_wccat(outstr, c);
    }
    /* add a trailing '\0' */
    if (!is_long)
        cstr_ccat(outstr, '\0');
    else
        cstr_wccat(outstr, '\0');
}

void parse_string(const char *s, int len)
{
    uint8_t buf[1000], *p = buf;
    int is_long, sep;

    if ((is_long = *s == 'L'))
        ++s, --len;
    sep = *s++;
    len -= 2;
    if (len >= sizeof buf)
        p = tcc_malloc(len + 1);
    memcpy(p, s, len);
    p[len] = 0;

    cstr_reset(&tokcstr);
    parse_escape_string(&tokcstr, p, is_long);
    if (p != buf)
        tcc_free(p);

    if (sep == '\'') {
        int char_size;
        /* XXX: make it portable */
        if (!is_long)
            char_size = 1;
        else
            char_size = sizeof(nwchar_t);
        if (tokcstr.size <= char_size)
            tcc_error("empty character constant");
        if (tokcstr.size > 2 * char_size)
            tcc_warning("multi-character character constant");
        if (!is_long) {
            tokc.i = *(int8_t *)tokcstr.data;
            tok = TOK_CCHAR;
        } else {
            tokc.i = *(nwchar_t *)tokcstr.data;
            tok = TOK_LCHAR;
        }
    } else {
        tokc.str.size = tokcstr.size;
        tokc.str.data = tokcstr.data;
        tokc.str.data_allocated = tokcstr.data_allocated;
        if (!is_long)
            tok = TOK_STR;
        else
            tok = TOK_LSTR;
    }
}

/* we use 64 bit numbers */
#define BN_SIZE 2

/* bn = (bn << shift) | or_val */
static void bn_lshift(unsigned int *bn, int shift, int or_val)
{
    int i;
    unsigned int v;
    for(i=0;i<BN_SIZE;i++) {
        v = bn[i];
        bn[i] = (v << shift) | or_val;
        or_val = v >> (32 - shift);
    }
}

static void bn_zero(unsigned int *bn)
{
    int i;
    for(i=0;i<BN_SIZE;i++) {
        bn[i] = 0;
    }
}

/* parse number in null terminated string 'p' and return it in the
   current token */
static void parse_number(const char *p)
{
    int b, t, shift, frac_bits, s, exp_val, ch;
    char *q;
    unsigned int bn[BN_SIZE];
    double d;

    /* number */
    q = token_buf;
    ch = *p++;
    t = ch;
    ch = *p++;
    *q++ = t;
    b = 10;
    if (t == '.') {
        goto float_frac_parse;
    } else if (t == '0') {
        if (ch == 'x' || ch == 'X') {
            q--;
            ch = *p++;
            b = 16;
        } else if (tcc_ext && (ch == 'b' || ch == 'B')) {
            q--;
            ch = *p++;
            b = 2;
        }
    }
    /* parse all digits. cannot check octal numbers at this stage
       because of floating point constants */
    while (1) {
        if (ch >= 'a' && ch <= 'f')
            t = ch - 'a' + 10;
        else if (ch >= 'A' && ch <= 'F')
            t = ch - 'A' + 10;
        else if (isnum(ch))
            t = ch - '0';
        else
            break;
        if (t >= b)
            break;
        if (q >= token_buf + STRING_MAX_SIZE) {
        num_too_long:
            tcc_error("number too long");
        }
        *q++ = ch;
        ch = *p++;
    }
    if (ch == '.' ||
        ((ch == 'e' || ch == 'E') && b == 10) ||
        ((ch == 'p' || ch == 'P') && (b == 16 || b == 2))) {
        if (b != 10) {
            /* NOTE: strtox should support that for hexa numbers, but
               non ISOC99 libcs do not support it, so we prefer to do
               it by hand */
            /* hexadecimal or binary floats */
            /* XXX: handle overflows */
            *q = '\0';
            if (b == 16)
                shift = 4;
            else 
                shift = 1;
            bn_zero(bn);
            q = token_buf;
            while (1) {
                t = *q++;
                if (t == '\0') {
                    break;
                } else if (t >= 'a') {
                    t = t - 'a' + 10;
                } else if (t >= 'A') {
                    t = t - 'A' + 10;
                } else {
                    t = t - '0';
                }
                bn_lshift(bn, shift, t);
            }
            frac_bits = 0;
            if (ch == '.') {
                ch = *p++;
                while (1) {
                    t = ch;
                    if (t >= 'a' && t <= 'f') {
                        t = t - 'a' + 10;
                    } else if (t >= 'A' && t <= 'F') {
                        t = t - 'A' + 10;
                    } else if (t >= '0' && t <= '9') {
                        t = t - '0';
                    } else {
                        break;
                    }
                    if (t >= b)
                        tcc_error("invalid digit");
                    bn_lshift(bn, shift, t);
                    frac_bits += shift;
                    ch = *p++;
                }
            }
            if (ch != 'p' && ch != 'P')
                expect("exponent");
            ch = *p++;
            s = 1;
            exp_val = 0;
            if (ch == '+') {
                ch = *p++;
            } else if (ch == '-') {
                s = -1;
                ch = *p++;
            }
            if (ch < '0' || ch > '9')
                expect("exponent digits");
            while (ch >= '0' && ch <= '9') {
                exp_val = exp_val * 10 + ch - '0';
                ch = *p++;
            }
            exp_val = exp_val * s;
            
            /* now we can generate the number */
            /* XXX: should patch directly float number */
            d = (double)bn[1] * 4294967296.0 + (double)bn[0];
            d = ldexp(d, exp_val - frac_bits);
            t = toup(ch);
            if (t == 'F') {
                ch = *p++;
                tok = TOK_CFLOAT;
                /* float : should handle overflow */
                tokc.f = (float)d;
            } else if (t == 'L') {
                ch = *p++;
#ifdef TCC_TARGET_PE
                tok = TOK_CDOUBLE;
                tokc.d = d;
#else
                tok = TOK_CLDOUBLE;
                /* XXX: not large enough */
                tokc.ld = (long double)d;
#endif
            } else {
                tok = TOK_CDOUBLE;
                tokc.d = d;
            }
        } else {
            /* decimal floats */
            if (ch == '.') {
                if (q >= token_buf + STRING_MAX_SIZE)
                    goto num_too_long;
                *q++ = ch;
                ch = *p++;
            float_frac_parse:
                while (ch >= '0' && ch <= '9') {
                    if (q >= token_buf + STRING_MAX_SIZE)
                        goto num_too_long;
                    *q++ = ch;
                    ch = *p++;
                }
            }
            if (ch == 'e' || ch == 'E') {
                if (q >= token_buf + STRING_MAX_SIZE)
                    goto num_too_long;
                *q++ = ch;
                ch = *p++;
                if (ch == '-' || ch == '+') {
                    if (q >= token_buf + STRING_MAX_SIZE)
                        goto num_too_long;
                    *q++ = ch;
                    ch = *p++;
                }
                if (ch < '0' || ch > '9')
                    expect("exponent digits");
                while (ch >= '0' && ch <= '9') {
                    if (q >= token_buf + STRING_MAX_SIZE)
                        goto num_too_long;
                    *q++ = ch;
                    ch = *p++;
                }
            }
            *q = '\0';
            t = toup(ch);
            errno = 0;
            if (t == 'F') {
                ch = *p++;
                tok = TOK_CFLOAT;
                tokc.f = strtof(token_buf, NULL);
            } else if (t == 'L') {
                ch = *p++;
#ifdef TCC_TARGET_PE
                tok = TOK_CDOUBLE;
                tokc.d = strtod(token_buf, NULL);
#else
                tok = TOK_CLDOUBLE;
                tokc.ld = strtold(token_buf, NULL);
#endif
            } else {
                tok = TOK_CDOUBLE;
                tokc.d = strtod(token_buf, NULL);
            }
        }
    } else {
        unsigned long long n, n1;
        int lcount, ucount, must_64bit;
        const char *p1;

        /* integer number */
        *q = '\0';
        q = token_buf;
        if (b == 10 && *q == '0') {
            b = 8;
            q++;
        }
        n = 0;
        while(1) {
            t = *q++;
            /* no need for checks except for base 10 / 8 errors */
            if (t == '\0')
                break;
            else if (t >= 'a')
                t = t - 'a' + 10;
            else if (t >= 'A')
                t = t - 'A' + 10;
            else
                t = t - '0';
            if (t >= b)
                tcc_error("invalid digit");
            n1 = n;
            n = n * b + t;
            /* detect overflow */
            /* XXX: this test is not reliable */
            if (n < n1)
                tcc_error("integer constant overflow");
        }

        /* Determine the characteristics (unsigned and/or 64bit) the type of
           the constant must have according to the constant suffix(es) */
        lcount = ucount = must_64bit = 0;
        p1 = p;
        for(;;) {
            t = toup(ch);
            if (t == 'L') {
                if (lcount >= 2)
                    tcc_error("three 'l's in integer constant");
                if (lcount && *(p - 1) != ch)
                    tcc_error("incorrect integer suffix: %s", p1);
                lcount++;
#if !defined TCC_TARGET_X86_64 || defined TCC_TARGET_PE
                if (lcount == 2)
#endif
                    must_64bit = 1;
                ch = *p++;
            } else if (t == 'U') {
                if (ucount >= 1)
                    tcc_error("two 'u's in integer constant");
                ucount++;
                ch = *p++;
            } else {
                break;
            }
        }

        /* Whether 64 bits are needed to hold the constant's value */
        if (n & 0xffffffff00000000LL || must_64bit) {
            tok = TOK_CLLONG;
            n1 = n >> 32;
	} else {
            tok = TOK_CINT;
            n1 = n;
        }

        /* Whether type must be unsigned to hold the constant's value */
        if (ucount || ((n1 >> 31) && (b != 10))) {
            if (tok == TOK_CLLONG)
                tok = TOK_CULLONG;
            else
                tok = TOK_CUINT;
        /* If decimal and no unsigned suffix, bump to 64 bits or throw error */
        } else if (n1 >> 31) {
            if (tok == TOK_CINT)
                tok = TOK_CLLONG;
            else
                tcc_error("integer constant overflow");
        }

        tokc.i = n;
    }
    if (ch)
        tcc_error("invalid number\n");
}


#define PARSE2(c1, tok1, c2, tok2)              \
    case c1:                                    \
        PEEKC(c, p);                            \
        if (c == c2) {                          \
            p++;                                \
            tok = tok2;                         \
        } else {                                \
            tok = tok1;                         \
        }                                       \
        break;

/* return next token without macro substitution */
static inline void next_nomacro1(void)
{
    int t, c, is_long, len;
    TokenSym *ts;
    uint8_t *p, *p1;
    unsigned int h;

    p = file->buf_ptr;
 redo_no_start:
    c = *p;
#if (__TINYC__ || __GNUC__)
#else
    if (c & 0x80)
        goto parse_ident_fast;
#endif
    switch(c) {
    case ' ':
    case '\t':
        tok = c;
        p++;
        if (parse_flags & PARSE_FLAG_SPACES)
            goto keep_tok_flags;
        while (isidnum_table[*p - CH_EOF] & IS_SPC)
            ++p;
        goto redo_no_start;
    case '\f':
    case '\v':
    case '\r':
        p++;
        goto redo_no_start;
    case '\\':
        /* first look if it is in fact an end of buffer */
        c = handle_stray1(p);
        p = file->buf_ptr;
        if (c == '\\')
            goto parse_simple;
        if (c != CH_EOF)
            goto redo_no_start;
        {
            TCCState *s1 = tcc_state;
            if ((parse_flags & PARSE_FLAG_LINEFEED)
                && !(tok_flags & TOK_FLAG_EOF)) {
                tok_flags |= TOK_FLAG_EOF;
                tok = TOK_LINEFEED;
                goto keep_tok_flags;
            } else if (!(parse_flags & PARSE_FLAG_PREPROCESS)) {
                tok = TOK_EOF;
            } else if (s1->ifdef_stack_ptr != file->ifdef_stack_ptr) {
                tcc_error("missing #endif");
            } else if (s1->include_stack_ptr == s1->include_stack) {
                /* no include left : end of file. */
                tok = TOK_EOF;
            } else {
                tok_flags &= ~TOK_FLAG_EOF;
                /* pop include file */
                
                /* test if previous '#endif' was after a #ifdef at
                   start of file */
                if (tok_flags & TOK_FLAG_ENDIF) {
#ifdef INC_DEBUG
                    printf("#endif %s\n", get_tok_str(file->ifndef_macro_saved, NULL));
#endif
                    add_cached_include(s1, file->filename, file->ifndef_macro_saved);
                    tok_flags &= ~TOK_FLAG_ENDIF;
                }

                /* add end of include file debug info */
                if (tcc_state->do_debug) {
                    put_stabd(N_EINCL, 0, 0);
                }
                /* pop include stack */
                tcc_close();
                s1->include_stack_ptr--;
                p = file->buf_ptr;
                goto redo_no_start;
            }
        }
        break;

    case '\n':
        file->line_num++;
        tok_flags |= TOK_FLAG_BOL;
        p++;
maybe_newline:
        if (0 == (parse_flags & PARSE_FLAG_LINEFEED))
            goto redo_no_start;
        tok = TOK_LINEFEED;
        goto keep_tok_flags;

    case '#':
        /* XXX: simplify */
        PEEKC(c, p);
        if ((tok_flags & TOK_FLAG_BOL) && 
            (parse_flags & PARSE_FLAG_PREPROCESS)) {
            file->buf_ptr = p;
            preprocess(tok_flags & TOK_FLAG_BOF);
            p = file->buf_ptr;
            goto maybe_newline;
        } else {
            if (c == '#') {
                p++;
                tok = TOK_TWOSHARPS;
            } else {
                if (parse_flags & PARSE_FLAG_ASM_FILE) {
                    p = parse_line_comment(p - 1);
                    goto redo_no_start;
                } else {
                    tok = '#';
                }
            }
        }
        break;
    
    /* dollar is allowed to start identifiers when not parsing asm */
    case '$':
        if (!(isidnum_table[c - CH_EOF] & IS_ID)
         || (parse_flags & PARSE_FLAG_ASM_FILE))
            goto parse_simple;

#if (__TINYC__ || __GNUC__)
    case 'a' ... 'z':
    case 'A' ... 'K':
    case 'M' ... 'Z':
    case '_':
    case 0x80 ... 0xFF:
#else
    case 'a': case 'b': case 'c': case 'd':
    case 'e': case 'f': case 'g': case 'h':
    case 'i': case 'j': case 'k': case 'l':
    case 'm': case 'n': case 'o': case 'p':
    case 'q': case 'r': case 's': case 't':
    case 'u': case 'v': case 'w': case 'x':
    case 'y': case 'z': 
    case 'A': case 'B': case 'C': case 'D':
    case 'E': case 'F': case 'G': case 'H':
    case 'I': case 'J': case 'K': 
    case 'M': case 'N': case 'O': case 'P':
    case 'Q': case 'R': case 'S': case 'T':
    case 'U': case 'V': case 'W': case 'X':
    case 'Y': case 'Z': 
    case '_':
#endif
    parse_ident_fast:
        p1 = p;
        h = TOK_HASH_INIT;
        h = TOK_HASH_FUNC(h, c);
        while (c = *++p, isidnum_table[c - CH_EOF] & (IS_ID|IS_NUM))
            h = TOK_HASH_FUNC(h, c);
        len = p - p1;
        if (c != '\\') {
            TokenSym **pts;

            /* fast case : no stray found, so we have the full token
               and we have already hashed it */
            h &= (TOK_HASH_SIZE - 1);
            pts = &hash_ident[h];
            for(;;) {
                ts = *pts;
                if (!ts)
                    break;
                if (ts->len == len && !memcmp(ts->str, p1, len))
                    goto token_found;
                pts = &(ts->hash_next);
            }
            ts = tok_alloc_new(pts, (char *) p1, len);
        token_found: ;
        } else {
            /* slower case */
            cstr_reset(&tokcstr);
            cstr_cat(&tokcstr, p1, len);
            p--;
            PEEKC(c, p);
        parse_ident_slow:
            while (isidnum_table[c - CH_EOF] & (IS_ID|IS_NUM))
            {
                cstr_ccat(&tokcstr, c);
                PEEKC(c, p);
            }
            ts = tok_alloc(tokcstr.data, tokcstr.size);
        }
        tok = ts->tok;
        break;
    case 'L':
        t = p[1];
        if (t != '\\' && t != '\'' && t != '\"') {
            /* fast case */
            goto parse_ident_fast;
        } else {
            PEEKC(c, p);
            if (c == '\'' || c == '\"') {
                is_long = 1;
                goto str_const;
            } else {
                cstr_reset(&tokcstr);
                cstr_ccat(&tokcstr, 'L');
                goto parse_ident_slow;
            }
        }
        break;

    case '0': case '1': case '2': case '3':
    case '4': case '5': case '6': case '7':
    case '8': case '9':
        cstr_reset(&tokcstr);
        /* after the first digit, accept digits, alpha, '.' or sign if
           prefixed by 'eEpP' */
    parse_num:
        for(;;) {
            t = c;
            cstr_ccat(&tokcstr, c);
            PEEKC(c, p);
            if (!((isidnum_table[c - CH_EOF] & (IS_ID|IS_NUM))
                  || c == '.'
                  || ((c == '+' || c == '-')
                      && (t == 'e' || t == 'E' || t == 'p' || t == 'P')
                      && !(parse_flags & PARSE_FLAG_ASM_FILE)
                      )))
                break;
        }
        /* We add a trailing '\0' to ease parsing */
        cstr_ccat(&tokcstr, '\0');
        tokc.str.size = tokcstr.size;
        tokc.str.data = tokcstr.data;
        tokc.str.data_allocated = tokcstr.data_allocated;
        tok = TOK_PPNUM;
        break;

    case '.':
        /* special dot handling because it can also start a number */
        PEEKC(c, p);
        if (isnum(c)) {
            cstr_reset(&tokcstr);
            cstr_ccat(&tokcstr, '.');
            goto parse_num;
        } else if ((parse_flags & PARSE_FLAG_ASM_FILE)
                   && (isidnum_table[c - CH_EOF] & (IS_ID|IS_NUM))) {
            *--p = c = '.';
            goto parse_ident_fast;
        } else if (c == '.') {
            PEEKC(c, p);
            if (c == '.') {
                p++;
                tok = TOK_DOTS;
            } else {
                *--p = '.'; /* may underflow into file->unget[] */
                tok = '.';
            }
        } else {
            tok = '.';
        }
        break;
    case '\'':
    case '\"':
        is_long = 0;
    str_const:
        cstr_reset(&tokcstr);
        if (is_long)
            cstr_ccat(&tokcstr, 'L');
        cstr_ccat(&tokcstr, c);
        p = parse_pp_string(p, c, &tokcstr);
        cstr_ccat(&tokcstr, c);
        cstr_ccat(&tokcstr, '\0');
        tokc.str.size = tokcstr.size;
        tokc.str.data = tokcstr.data;
        tokc.str.data_allocated = tokcstr.data_allocated;
        tok = TOK_PPSTR;
        break;

    case '<':
        PEEKC(c, p);
        if (c == '=') {
            p++;
            tok = TOK_LE;
        } else if (c == '<') {
            PEEKC(c, p);
            if (c == '=') {
                p++;
                tok = TOK_A_SHL;
            } else {
                tok = TOK_SHL;
            }
        } else {
            tok = TOK_LT;
        }
        break;
    case '>':
        PEEKC(c, p);
        if (c == '=') {
            p++;
            tok = TOK_GE;
        } else if (c == '>') {
            PEEKC(c, p);
            if (c == '=') {
                p++;
                tok = TOK_A_SAR;
            } else {
                tok = TOK_SAR;
            }
        } else {
            tok = TOK_GT;
        }
        break;
        
    case '&':
        PEEKC(c, p);
        if (c == '&') {
            p++;
            tok = TOK_LAND;
        } else if (c == '=') {
            p++;
            tok = TOK_A_AND;
        } else {
            tok = '&';
        }
        break;
        
    case '|':
        PEEKC(c, p);
        if (c == '|') {
            p++;
            tok = TOK_LOR;
        } else if (c == '=') {
            p++;
            tok = TOK_A_OR;
        } else {
            tok = '|';
        }
        break;

    case '+':
        PEEKC(c, p);
        if (c == '+') {
            p++;
            tok = TOK_INC;
        } else if (c == '=') {
            p++;
            tok = TOK_A_ADD;
        } else {
            tok = '+';
        }
        break;
        
    case '-':
        PEEKC(c, p);
        if (c == '-') {
            p++;
            tok = TOK_DEC;
        } else if (c == '=') {
            p++;
            tok = TOK_A_SUB;
        } else if (c == '>') {
            p++;
            tok = TOK_ARROW;
        } else {
            tok = '-';
        }
        break;

    PARSE2('!', '!', '=', TOK_NE)
    PARSE2('=', '=', '=', TOK_EQ)
    PARSE2('*', '*', '=', TOK_A_MUL)
    PARSE2('%', '%', '=', TOK_A_MOD)
    PARSE2('^', '^', '=', TOK_A_XOR)
        
        /* comments or operator */
    case '/':
        PEEKC(c, p);
        if (c == '*') {
            p = parse_comment(p);
            /* comments replaced by a blank */
            tok = ' ';
            goto keep_tok_flags;
        } else if (c == '/') {
            p = parse_line_comment(p);
            tok = ' ';
            goto keep_tok_flags;
        } else if (c == '=') {
            p++;
            tok = TOK_A_DIV;
        } else {
            tok = '/';
        }
        break;
        
        /* simple tokens */
    case '(':
    case ')':
    case '[':
    case ']':
    case '{':
    case '}':
    case ',':
    case ';':
    case ':':
    case '?':
    case '~':
    case '@': /* only used in assembler */
    parse_simple:
        tok = c;
        p++;
        break;
    default:
        if (parse_flags & PARSE_FLAG_ASM_FILE)
            goto parse_simple;
        tcc_error("unrecognized character \\x%02x", c);
        break;
    }
    tok_flags = 0;
keep_tok_flags:
    file->buf_ptr = p;
#if defined(PARSE_DEBUG)
    printf("token = %s\n", get_tok_str(tok, &tokc));
#endif
}

/* return next token without macro substitution. Can read input from
   macro_ptr buffer */
static void next_nomacro_spc(void)
{
    if (macro_ptr) {
    redo:
        tok = *macro_ptr;
        if (tok) {
            TOK_GET(&tok, &macro_ptr, &tokc);
            if (tok == TOK_LINENUM) {
                file->line_num = tokc.i;
                goto redo;
            }
        }
    } else {
        next_nomacro1();
    }
}

ST_FUNC void next_nomacro(void)
{
    do {
        next_nomacro_spc();
    } while (tok < 256 && (isidnum_table[tok - CH_EOF] & IS_SPC));
}
 

static void macro_subst(
    TokenString *tok_str,
    Sym **nested_list,
    const int *macro_str,
    int can_read_stream
    );

/* substitute arguments in replacement lists in macro_str by the values in
   args (field d) and return allocated string */
static int *macro_arg_subst(Sym **nested_list, const int *macro_str, Sym *args)
{
    int t, t0, t1, spc;
    const int *st;
    Sym *s;
    CValue cval;
    TokenString str;
    CString cstr;

    tok_str_new(&str);
    t0 = t1 = 0;
    while(1) {
        TOK_GET(&t, &macro_str, &cval);
        if (!t)
            break;
        if (t == '#') {
            /* stringize */
            TOK_GET(&t, &macro_str, &cval);
            if (!t)
                goto bad_stringy;
            s = sym_find2(args, t);
            if (s) {
                cstr_new(&cstr);
                cstr_ccat(&cstr, '\"');
                st = s->d;
                spc = 0;
                while (*st) {
                    TOK_GET(&t, &st, &cval);
                    if (t != TOK_PLCHLDR
                     && t != TOK_NOSUBST
                     && 0 == check_space(t, &spc)) {
                        const char *s = get_tok_str(t, &cval);
                        while (*s) {
                            if (t == TOK_PPSTR && *s != '\'')
                                add_char(&cstr, *s);
                            else
                                cstr_ccat(&cstr, *s);
                            ++s;
                        }
                    }
                }
                cstr.size -= spc;
                cstr_ccat(&cstr, '\"');
                cstr_ccat(&cstr, '\0');
#ifdef PP_DEBUG
                printf("\nstringize: <%s>\n", (char *)cstr.data);
#endif
                /* add string */
                cval.str.size = cstr.size;
                cval.str.data = cstr.data;
                cval.str.data_allocated = cstr.data_allocated;
                tok_str_add2(&str, TOK_PPSTR, &cval);
                cstr_free(&cstr);
            } else {
        bad_stringy:
                expect("macro parameter after '#'");
            }
        } else if (t >= TOK_IDENT) {
            s = sym_find2(args, t);
            if (s) {
                int l0 = str.len;
                st = s->d;
                /* if '##' is present before or after, no arg substitution */
                if (*macro_str == TOK_TWOSHARPS || t1 == TOK_TWOSHARPS) {
                    /* special case for var arg macros : ## eats the ','
                       if empty VA_ARGS variable. */
                    if (t1 == TOK_TWOSHARPS && t0 == ',' && gnu_ext && s->type.t) {
                        if (*st == 0) {
                            /* suppress ',' '##' */
                            str.len -= 2;
                        } else {
                            /* suppress '##' and add variable */
                            str.len--;
                            goto add_var;
                        }
                    } else {
                        for(;;) {
                            int t1;
                            TOK_GET(&t1, &st, &cval);
                            if (!t1)
                                break;
                            tok_str_add2(&str, t1, &cval);
                        }
                    }

                } else {
            add_var:
                    /* NOTE: the stream cannot be read when macro
                       substituing an argument */
                    macro_subst(&str, nested_list, st, 0);
                }
                if (str.len == l0) /* exanded to empty string */
                    tok_str_add(&str, TOK_PLCHLDR);
            } else {
                tok_str_add(&str, t);
            }
        } else {
            tok_str_add2(&str, t, &cval);
        }
        t0 = t1, t1 = t;
    }
    tok_str_add(&str, 0);
    return str.str;
}

static char const ab_month_name[12][4] =
{
    "Jan", "Feb", "Mar", "Apr", "May", "Jun",
    "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"
};

/* peek or read [ws_str == NULL] next token from function macro call,
   walking up macro levels up to the file if necessary */
static int next_argstream(Sym **nested_list, int can_read_stream, TokenString *ws_str)
{
    int t;
    const int *p;
    Sym *sa;

    for (;;) {
        if (macro_ptr) {
            p = macro_ptr, t = *p;
            if (ws_str) {
                while (is_space(t) || TOK_LINEFEED == t)
                    tok_str_add(ws_str, t), t = *++p;
            }
            if (t == 0 && can_read_stream) {
                end_macro();
                /* also, end of scope for nested defined symbol */
                sa = *nested_list;
                while (sa && sa->v == 0)
                    sa = sa->prev;
                if (sa)
                    sa->v = 0;
                continue;
            }
        } else {
            ch = handle_eob();
            if (ws_str) {
                while (is_space(ch) || ch == '\n' || ch == '/') {
                    if (ch == '/') {
                        int c;
                        uint8_t *p = file->buf_ptr;
                        PEEKC(c, p);
                        if (c == '*') {
                            p = parse_comment(p);
                            file->buf_ptr = p - 1;
                        } else if (c == '/') {
                            p = parse_line_comment(p);
                            file->buf_ptr = p - 1;
                        } else
                            break;
                        ch = ' ';
                    }
                    tok_str_add(ws_str, ch);
                    cinp();
                }
            }
            t = ch;
        }

        if (ws_str)
            return t;
        next_nomacro_spc();
        return tok;
    }
}

/* do macro substitution of current token with macro 's' and add
   result to (tok_str,tok_len). 'nested_list' is the list of all
   macros we got inside to avoid recursing. Return non zero if no
   substitution needs to be done */
static int macro_subst_tok(
    TokenString *tok_str,
    Sym **nested_list,
    Sym *s,
    int can_read_stream)
{
    Sym *args, *sa, *sa1;
    int parlevel, *mstr, t, t1, spc;
    TokenString str;
    char *cstrval;
    CValue cval;
    CString cstr;
    char buf[32];
    
    /* if symbol is a macro, prepare substitution */
    /* special macros */
    if (tok == TOK___LINE__) {
        snprintf(buf, sizeof(buf), "%d", file->line_num);
        cstrval = buf;
        t1 = TOK_PPNUM;
        goto add_cstr1;
    } else if (tok == TOK___FILE__) {
        cstrval = file->filename;
        goto add_cstr;
    } else if (tok == TOK___DATE__ || tok == TOK___TIME__) {
        time_t ti;
        struct tm *tm;

        time(&ti);
        tm = localtime(&ti);
        if (tok == TOK___DATE__) {
            snprintf(buf, sizeof(buf), "%s %2d %d", 
                     ab_month_name[tm->tm_mon], tm->tm_mday, tm->tm_year + 1900);
        } else {
            snprintf(buf, sizeof(buf), "%02d:%02d:%02d", 
                     tm->tm_hour, tm->tm_min, tm->tm_sec);
        }
        cstrval = buf;
    add_cstr:
        t1 = TOK_STR;
    add_cstr1:
        cstr_new(&cstr);
        cstr_cat(&cstr, cstrval, 0);
        cval.str.size = cstr.size;
        cval.str.data = cstr.data;
        cval.str.data_allocated = cstr.data_allocated;
        tok_str_add2(tok_str, t1, &cval);
        cstr_free(&cstr);
    } else {
        int saved_parse_flags = parse_flags;

        mstr = s->d;
        if (s->type.t == MACRO_FUNC) {
            /* whitespace between macro name and argument list */
            TokenString ws_str;
            tok_str_new(&ws_str);

            spc = 0;
            parse_flags |= PARSE_FLAG_SPACES | PARSE_FLAG_LINEFEED
                | PARSE_FLAG_ACCEPT_STRAYS;

            /* get next token from argument stream */
            t = next_argstream(nested_list, can_read_stream, &ws_str);
            if (t != '(') {
                /* not a macro substitution after all, restore the
                 * macro token plus all whitespace we've read.
                 * whitespace is intentionally not merged to preserve
                 * newlines. */
                parse_flags = saved_parse_flags;
                tok_str_add(tok_str, tok);
                if (parse_flags & PARSE_FLAG_SPACES) {
                    int i;
                    for (i = 0; i < ws_str.len; i++)
                        tok_str_add(tok_str, ws_str.str[i]);
                }
                tok_str_free(ws_str.str);
                return 0;
            } else {
                tok_str_free(ws_str.str);
            }
            next_nomacro(); /* eat '(' */

            /* argument macro */
            args = NULL;
            sa = s->next;
            /* NOTE: empty args are allowed, except if no args */
            for(;;) {
                do {
                    next_argstream(nested_list, can_read_stream, NULL);
                } while (is_space(tok) || TOK_LINEFEED == tok);
    empty_arg:
                /* handle '()' case */
                if (!args && !sa && tok == ')')
                    break;
                if (!sa)
                    tcc_error("macro '%s' used with too many args",
                          get_tok_str(s->v, 0));
                tok_str_new(&str);
                parlevel = spc = 0;
                /* NOTE: non zero sa->t indicates VA_ARGS */
                while ((parlevel > 0 || 
                        (tok != ')' && 
                         (tok != ',' || sa->type.t)))) {
                    if (tok == TOK_EOF || tok == 0)
                        break;
                    if (tok == '(')
                        parlevel++;
                    else if (tok == ')')
                        parlevel--;
                    if (tok == TOK_LINEFEED)
                        tok = ' ';
                    if (!check_space(tok, &spc))
                        tok_str_add2(&str, tok, &tokc);
                    next_argstream(nested_list, can_read_stream, NULL);
                }
                if (parlevel)
                    expect(")");
                str.len -= spc;
                tok_str_add(&str, 0);
                sa1 = sym_push2(&args, sa->v & ~SYM_FIELD, sa->type.t, 0);
                sa1->d = str.str;
                sa = sa->next;
                if (tok == ')') {
                    /* special case for gcc var args: add an empty
                       var arg argument if it is omitted */
                    if (sa && sa->type.t && gnu_ext)
                        goto empty_arg;
                    break;
                }
                if (tok != ',')
                    expect(",");
            }
            if (sa) {
                tcc_error("macro '%s' used with too few args",
                      get_tok_str(s->v, 0));
            }

            parse_flags = saved_parse_flags;

            /* now subst each arg */
            mstr = macro_arg_subst(nested_list, mstr, args);
            /* free memory */
            sa = args;
            while (sa) {
                sa1 = sa->prev;
                tok_str_free(sa->d);
                sym_free(sa);
                sa = sa1;
            }
        }

        sym_push2(nested_list, s->v, 0, 0);
        parse_flags = saved_parse_flags;
        macro_subst(tok_str, nested_list, mstr, can_read_stream | 2);

        /* pop nested defined symbol */
        sa1 = *nested_list;
        *nested_list = sa1->prev;
        sym_free(sa1);
        if (mstr != s->d)
            tok_str_free(mstr);
    }
    return 0;
}

int paste_tokens(int t1, CValue *v1, int t2, CValue *v2)
{
    CString cstr;
    int n;

    cstr_new(&cstr);
    if (t1 != TOK_PLCHLDR)
        cstr_cat(&cstr, get_tok_str(t1, v1), -1);
    n = cstr.size;
    if (t2 != TOK_PLCHLDR)
        cstr_cat(&cstr, get_tok_str(t2, v2), -1);
    cstr_ccat(&cstr, '\0');

    tcc_open_bf(tcc_state, ":paste:", cstr.size);
    memcpy(file->buffer, cstr.data, cstr.size);
    for (;;) {
        next_nomacro1();
        if (0 == *file->buf_ptr)
            break;
        if (is_space(tok))
            continue;
        tcc_warning("pasting <%.*s> and <%s> does not give a valid preprocessing token",
            n, cstr.data, (char*)cstr.data + n);
        break;
    }
    tcc_close();

    //printf("paste <%s>\n", (char*)cstr.data);
    cstr_free(&cstr);
    return 0;
}

/* handle the '##' operator. Return NULL if no '##' seen. Otherwise
   return the resulting string (which must be freed). */
static inline int *macro_twosharps(const int *ptr0)
{
    int t;
    CValue cval;
    TokenString macro_str1;
    int start_of_nosubsts = -1;
    const int *ptr;

    /* we search the first '##' */
    for (ptr = ptr0;;) {
        TOK_GET(&t, &ptr, &cval);
        if (t == TOK_TWOSHARPS)
            break;
        if (t == 0)
            return NULL;
    }

    tok_str_new(&macro_str1);

    //tok_print(" $$$", ptr0);
    for (ptr = ptr0;;) {
        TOK_GET(&t, &ptr, &cval);
        if (t == 0)
            break;
        if (t == TOK_TWOSHARPS)
            continue;
        while (*ptr == TOK_TWOSHARPS) {
            int t1; CValue cv1;
            /* given 'a##b', remove nosubsts preceding 'a' */
            if (start_of_nosubsts >= 0)
                macro_str1.len = start_of_nosubsts;
            /* given 'a##b', remove nosubsts preceding 'b' */
            while ((t1 = *++ptr) == TOK_NOSUBST)
                ;
            if (t1 && t1 != TOK_TWOSHARPS 
                && t1 != ':') /* 'a##:' don't build a new token */
            {
                TOK_GET(&t1, &ptr, &cv1);
                if (t != TOK_PLCHLDR || t1 != TOK_PLCHLDR) {
                    paste_tokens(t, &cval, t1, &cv1);
                    t = tok, cval = tokc;
                }
            }
        }
        if (t == TOK_NOSUBST) {
            if (start_of_nosubsts < 0)
                start_of_nosubsts = macro_str1.len;
        } else {
            start_of_nosubsts = -1;
        }
        tok_str_add2(&macro_str1, t, &cval);
    }
    tok_str_add(&macro_str1, 0);
    //tok_print(" ###", macro_str1.str);
    return macro_str1.str;
}

/* do macro substitution of macro_str and add result to
   (tok_str,tok_len). 'nested_list' is the list of all macros we got
   inside to avoid recursing. */
static void macro_subst(
    TokenString *tok_str,
    Sym **nested_list,
    const int *macro_str,
    int can_read_stream
    )
{
    Sym *s;
    const int *ptr;
    int t, spc, nosubst;
    CValue cval;
    int *macro_str1 = NULL;
    
    /* first scan for '##' operator handling */
    ptr = macro_str;
    spc = nosubst = 0;

    /* first scan for '##' operator handling */
    if (can_read_stream & 1) {
        macro_str1 = macro_twosharps(ptr);
        if (macro_str1)
            ptr = macro_str1;
    }

    while (1) {
        TOK_GET(&t, &ptr, &cval);
        if (t == 0)
            break;

        if (t >= TOK_IDENT && 0 == nosubst) {
            s = define_find(t);
            if (s == NULL)
                goto no_subst;

            /* if nested substitution, do nothing */
            if (sym_find2(*nested_list, t)) {
                /* and mark it as TOK_NOSUBST, so it doesn't get subst'd again */
                tok_str_add2(tok_str, TOK_NOSUBST, NULL);
                goto no_subst;
            }

            {
                TokenString str;
                str.str = (int*)ptr;
                begin_macro(&str, 2);

                tok = t;
                macro_subst_tok(tok_str, nested_list, s, can_read_stream);

                if (str.alloc == 3) {
                    /* already finished by reading function macro arguments */
                    break;
                }

                ptr = macro_ptr;
                end_macro ();
            }

            spc = (tok_str->len &&
                   is_space(tok_last(tok_str->str,
                                     tok_str->str + tok_str->len)));

        } else {

            if (t == '\\' && !(parse_flags & PARSE_FLAG_ACCEPT_STRAYS))
                tcc_error("stray '\\' in program");

no_subst:
            if (!check_space(t, &spc))
                tok_str_add2(tok_str, t, &cval);
            nosubst = 0;
            if (t == TOK_NOSUBST)
                nosubst = 1;
        }
    }
    if (macro_str1)
        tok_str_free(macro_str1);

}

/* return next token with macro substitution */
ST_FUNC void next(void)
{
 redo:
    if (parse_flags & PARSE_FLAG_SPACES)
        next_nomacro_spc();
    else
        next_nomacro();

    if (macro_ptr) {
        if (tok == TOK_NOSUBST || tok == TOK_PLCHLDR) {
        /* discard preprocessor markers */
            goto redo;
        } else if (tok == 0) {
            /* end of macro or unget token string */
            end_macro();
            goto redo;
        }
    } else if (tok >= TOK_IDENT && (parse_flags & PARSE_FLAG_PREPROCESS)) {
        Sym *s;
        /* if reading from file, try to substitute macros */
        s = define_find(tok);
        if (s) {
            Sym *nested_list = NULL;
            tokstr_buf.len = 0;
            nested_list = NULL;
            macro_subst_tok(&tokstr_buf, &nested_list, s, 1);
            tok_str_add(&tokstr_buf, 0);
            begin_macro(&tokstr_buf, 2);
            goto redo;
        }
    }
    /* convert preprocessor tokens into C tokens */
    if (tok == TOK_PPNUM) {
        if  (parse_flags & PARSE_FLAG_TOK_NUM)
            parse_number((char *)tokc.str.data);
    } else if (tok == TOK_PPSTR) {
        if (parse_flags & PARSE_FLAG_TOK_STR)
            parse_string((char *)tokc.str.data, tokc.str.size - 1);
    }
}

/* push back current token and set current token to 'last_tok'. Only
   identifier case handled for labels. */
ST_INLN void unget_tok(int last_tok)
{
    TokenString *str = tcc_malloc(sizeof *str);
    tok_str_new(str);
    tok_str_add2(str, tok, &tokc);
    tok_str_add(str, 0);
    begin_macro(str, 1);
    tok = last_tok;
}

ST_FUNC void preprocess_init(TCCState *s1)
{
    s1->include_stack_ptr = s1->include_stack;
    /* XXX: move that before to avoid having to initialize
       file->ifdef_stack_ptr ? */
    s1->ifdef_stack_ptr = s1->ifdef_stack;
    file->ifdef_stack_ptr = s1->ifdef_stack_ptr;

    pvtop = vtop = vstack - 1;
    s1->pack_stack[0] = 0;
    s1->pack_stack_ptr = s1->pack_stack;

    isidnum_table['$' - CH_EOF] =
        s1->dollars_in_identifiers ? IS_ID : 0;
    isidnum_table['.' - CH_EOF] =
        (parse_flags & PARSE_FLAG_ASM_FILE) ? IS_ID : 0;
}

ST_FUNC void preprocess_new(void)
{
    int i, c;
    const char *p, *r;

    /* init isid table */
    for(i = CH_EOF; i<128; i++)
        isidnum_table[i - CH_EOF]
            = is_space(i) ? IS_SPC
            : isid(i) ? IS_ID
            : isnum(i) ? IS_NUM
            : 0;

    for(i = 128; i<256; i++)
        isidnum_table[i - CH_EOF] = IS_ID;

    /* init allocators */
    tal_new(&toksym_alloc, TOKSYM_TAL_LIMIT, TOKSYM_TAL_SIZE);
    tal_new(&tokstr_alloc, TOKSTR_TAL_LIMIT, TOKSTR_TAL_SIZE);
    tal_new(&cstr_alloc, CSTR_TAL_LIMIT, CSTR_TAL_SIZE);

    memset(hash_ident, 0, TOK_HASH_SIZE * sizeof(TokenSym *));
    cstr_new(&cstr_buf);
    cstr_realloc(&cstr_buf, STRING_MAX_SIZE);
    tok_str_new(&tokstr_buf);
    tok_str_realloc(&tokstr_buf, TOKSTR_MAX_SIZE);
    
    tok_ident = TOK_IDENT;
    p = tcc_keywords;
    while (*p) {
        r = p;
        for(;;) {
            c = *r++;
            if (c == '\0')
                break;
        }
        tok_alloc(p, r - p - 1);
        p = r;
    }
}

ST_FUNC void preprocess_delete(void)
{
    int i, n;

    /* free -D and compiler defines */
    free_defines(NULL);

    /* cleanup from error/setjmp */
    while (macro_stack)
        end_macro();
    macro_ptr = NULL;

    /* free tokens */
    n = tok_ident - TOK_IDENT;
    for(i = 0; i < n; i++)
        tal_free(toksym_alloc, table_ident[i]);
    tcc_free(table_ident);
    table_ident = NULL;

    /* free static buffers */
    cstr_free(&tokcstr);
    cstr_free(&cstr_buf);
    tok_str_free(tokstr_buf.str);

    /* free allocators */
    tal_delete(toksym_alloc);
    toksym_alloc = NULL;
    tal_delete(tokstr_alloc);
    tokstr_alloc = NULL;
    tal_delete(cstr_alloc);
    cstr_alloc = NULL;
}

/* ------------------------------------------------------------------------- */
/* tcc -E [-P[1]] [-dD} support */

static void tok_print(const char *msg, const int *str)
{
    FILE *fp;
    int t;
    CValue cval;

    fp = tcc_state->ppfp;
    if (!fp || !tcc_state->dflag)
        fp = stdout;

    fprintf(fp, "%s ", msg);
    while (str) {
	TOK_GET(&t, &str, &cval);
	if (!t)
	    break;
	fprintf(fp,"%s", get_tok_str(t, &cval));
    }
    fprintf(fp, "\n");
}

static void pp_line(TCCState *s1, BufferedFile *f, int level)
{
    int d = f->line_num - f->line_ref;

    if (s1->dflag & 4)
	return;

    if (s1->Pflag == LINE_MACRO_OUTPUT_FORMAT_NONE) {
	if (level == 0 && f->line_ref && d) {
	    d = 1;
	    goto simple;
	}
    } else if (level == 0 && f->line_ref && d < 8) {
simple:
	while (d > 0)
	    fputs("\n", s1->ppfp), --d;
    } else if (s1->Pflag == LINE_MACRO_OUTPUT_FORMAT_STD) {
	fprintf(s1->ppfp, "#line %d \"%s\"\n", f->line_num, f->filename);
    } else {
	fprintf(s1->ppfp, "# %d \"%s\"%s\n", f->line_num, f->filename,
	    level > 0 ? " 1" : level < 0 ? " 2" : "");
    }
    f->line_ref = f->line_num;
}

static void define_print(TCCState *s1, int v)
{
    FILE *fp;
    Sym *s;

    s = define_find(v);
    if (NULL == s || NULL == s->d)
        return;

    fp = s1->ppfp;
    fprintf(fp, "#define %s", get_tok_str(v, NULL));
    if (s->type.t == MACRO_FUNC) {
        Sym *a = s->next;
        fprintf(fp,"(");
        if (a)
            for (;;) {
                fprintf(fp,"%s", get_tok_str(a->v & ~SYM_FIELD, NULL));
                if (!(a = a->next))
                    break;
                fprintf(fp,",");
            }
        fprintf(fp,")");
    }
    tok_print("", s->d);
}

static void pp_debug_defines(TCCState *s1)
{
    int v, t;
    const char *vs;
    FILE *fp;

    t = pp_debug_tok;
    if (t == 0)
        return;

    file->line_num--;
    pp_line(s1, file, 0);
    file->line_ref = ++file->line_num;

    fp = s1->ppfp;
    v = pp_debug_symv;
    vs = get_tok_str(v, NULL);
    if (t == TOK_DEFINE) {
        define_print(s1, v);
    } else if (t == TOK_UNDEF) {
        fprintf(fp, "#undef %s\n", vs);
    } else if (t == TOK_push_macro) {
        fprintf(fp, "#pragma push_macro(\"%s\")\n", vs);
    } else if (t == TOK_pop_macro) {
        fprintf(fp, "#pragma pop_macro(\"%s\")\n", vs);
    }
    pp_debug_tok = 0;
}

static void pp_debug_builtins(TCCState *s1)
{
    int v;
    for (v = TOK_IDENT; v < tok_ident; ++v)
        define_print(s1, v);
}

static int need_space(int prev_tok, int tok, const char *tokstr)
{
    const char *sp_chars = "";
    if ((prev_tok >= TOK_IDENT || prev_tok == TOK_PPNUM) &&
        (tok >= TOK_IDENT || tok == TOK_PPNUM))
        return 1;
    switch (prev_tok) {
    case '+':
        sp_chars = "+=";
        break;
    case '-':
        sp_chars = "-=>";
        break;
    case '*':
    case '/':
    case '%':
    case '^':
    case '=':
    case '!':
    case TOK_A_SHL:
    case TOK_A_SAR:
        sp_chars = "=";
        break;
    case '&':
        sp_chars = "&=";
        break;
    case '|':
        sp_chars = "|=";
        break;
    case '<':
        sp_chars = "<=";
        break;
    case '>':
        sp_chars = ">=";
        break;
    case '.':
        sp_chars = ".";
        break;
    case '#':
        sp_chars = "#";
        break;
    case TOK_PPNUM:
        sp_chars = "+-";
        break;
    }
    return !!strchr(sp_chars, tokstr[0]);
}

/* Preprocess the current file */
ST_FUNC int tcc_preprocess(TCCState *s1)
{
    BufferedFile **iptr;
    int token_seen, spcs, level;
    Sym *define_start;
    const char *tokstr;

    preprocess_init(s1);
    ch = file->buf_ptr[0];
    tok_flags = TOK_FLAG_BOL | TOK_FLAG_BOF;
    parse_flags = PARSE_FLAG_PREPROCESS
                | (parse_flags & PARSE_FLAG_ASM_FILE)
                | PARSE_FLAG_LINEFEED
                | PARSE_FLAG_SPACES
                | PARSE_FLAG_ACCEPT_STRAYS
                ;
    define_start = define_stack;

    /* Credits to Fabrice Bellard's initial revision to demonstrate its
       capability to compile and run itself, provided all numbers are
       given as decimals. tcc -E -P10 will do. */
    if (s1->Pflag == 1 + 10)
        parse_flags |= PARSE_FLAG_TOK_NUM, s1->Pflag = 1;

#ifdef PP_BENCH
    /* for PP benchmarks */
    do next(); while (tok != TOK_EOF); return 0;
#endif

    if (s1->dflag & 1) {
        pp_debug_builtins(s1);
        s1->dflag &= ~1;
    }

    token_seen = TOK_LINEFEED, spcs = 0;
    pp_line(s1, file, 0);

    for (;;) {
        iptr = s1->include_stack_ptr;
        next();
        if (tok == TOK_EOF)
            break;
        level = s1->include_stack_ptr - iptr;
        if (level) {
            if (level > 0)
                pp_line(s1, *iptr, 0);
            pp_line(s1, file, level);
        }

        if (s1->dflag) {
            pp_debug_defines(s1);
            if (s1->dflag & 4)
                continue;
        }

        if (token_seen == TOK_LINEFEED) {
            if (tok == ' ') {
                ++spcs;
                continue;
            }
            if (tok == TOK_LINEFEED) {
                spcs = 0;
                continue;
            }
            pp_line(s1, file, 0);
        } else if (tok == TOK_LINEFEED) {
            ++file->line_ref;
        }

        tokstr = get_tok_str(tok, &tokc);
        if (!spcs && need_space(token_seen, tok, tokstr))
            ++spcs;
        while (spcs)
            fputs(" ", s1->ppfp), --spcs;
        fputs(tokstr, s1->ppfp);

        token_seen = tok;
    }
    /* reset define stack, but keep -D and built-ins */
    free_defines(define_start);
    return 0;
}

/* ------------------------------------------------------------------------- */
