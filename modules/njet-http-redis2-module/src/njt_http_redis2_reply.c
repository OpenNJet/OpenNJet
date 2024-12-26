#ifndef DDEBUG
#define DDEBUG 0
#endif
#include "ddebug.h"

#include "njt_http_redis2_reply.h"
#include "njt_http_redis2_util.h"
#include <njet.h>


static const unsigned char _reply_cond_offsets[] = {
	0, 0, 0, 0, 0, 0, 0, 0, 
	0, 0, 0, 0, 1, 4, 7, 7, 
	7, 7, 7, 7, 7, 7, 11, 14, 
	15, 17, 18, 21, 26, 28, 29, 30, 
	32, 33, 34, 37, 42, 50, 55, 60, 
	65, 70, 73, 74, 79, 82, 87, 92, 
	97, 98, 103, 103, 103, 103, 106, 110, 
	121, 126, 137
};

static const char _reply_cond_lengths[] = {
	0, 0, 0, 0, 0, 0, 0, 0, 
	0, 0, 0, 1, 3, 3, 0, 0, 
	0, 0, 0, 0, 0, 4, 3, 1, 
	2, 1, 3, 5, 2, 1, 1, 2, 
	1, 1, 3, 5, 8, 5, 5, 5, 
	5, 3, 1, 5, 3, 5, 5, 5, 
	1, 5, 0, 0, 0, 3, 4, 11, 
	5, 11, 9
};

static const short _reply_cond_keys[] = {
	-128, 127, -128, 12, 13, 13, 14, 127, 
	-128, 12, 13, 13, 14, 127, 36, 36, 
	43, 43, 45, 45, 58, 58, 45, 45, 
	48, 48, 49, 57, 48, 57, 13, 13, 
	48, 57, 10, 10, -128, 12, 13, 13, 
	14, 127, -128, 9, 10, 10, 11, 12, 
	13, 13, 14, 127, 13, 13, 48, 48, 
	10, 10, 13, 13, 13, 13, 48, 57, 
	10, 10, -128, 127, -128, 12, 13, 13, 
	14, 127, -128, 9, 10, 10, 11, 12, 
	13, 13, 14, 127, -128, 12, 13, 13, 
	14, 44, 45, 45, 46, 47, 48, 48, 
	49, 57, 58, 127, -128, 12, 13, 13, 
	14, 47, 48, 57, 58, 127, -128, 12, 
	13, 13, 14, 47, 48, 57, 58, 127, 
	-128, 12, 13, 13, 14, 47, 48, 48, 
	49, 127, -128, 9, 10, 10, 11, 12, 
	13, 13, 14, 127, -128, 12, 13, 13, 
	14, 127, 10, 10, -128, 9, 10, 10, 
	11, 12, 13, 13, 14, 127, -128, 12, 
	13, 13, 14, 127, -128, 9, 10, 10, 
	11, 12, 13, 13, 14, 127, -128, 12, 
	13, 13, 14, 47, 48, 57, 58, 127, 
	-128, 9, 10, 10, 11, 12, 13, 13, 
	14, 127, 10, 10, -128, 9, 10, 10, 
	11, 12, 13, 13, 14, 127, -128, 12, 
	13, 13, 14, 127, 36, 36, 43, 43, 
	45, 45, 58, 58, -128, 12, 13, 13, 
	14, 35, 36, 36, 37, 42, 43, 43, 
	44, 44, 45, 45, 46, 57, 58, 58, 
	59, 127, 13, 13, 36, 36, 43, 43, 
	45, 45, 58, 58, -128, 12, 13, 13, 
	14, 35, 36, 36, 37, 42, 43, 43, 
	44, 44, 45, 45, 46, 57, 58, 58, 
	59, 127, -128, 35, 36, 36, 37, 42, 
	43, 43, 44, 44, 45, 45, 46, 57, 
	58, 58, 59, 127, 0
};

static const char _reply_cond_spaces[] = {
	0, 0, 3, 0, 0, 3, 0, 2, 
	2, 2, 2, 2, 2, 2, 2, 2, 
	2, 2, 2, 2, 2, 2, 2, 2, 
	2, 2, 2, 2, 2, 2, 2, 2, 
	2, 4, 4, 5, 4, 4, 4, 4, 
	5, 4, 4, 5, 4, 4, 4, 4, 
	4, 4, 4, 5, 4, 4, 4, 4, 
	5, 4, 4, 4, 4, 5, 4, 4, 
	4, 4, 4, 4, 5, 4, 4, 5, 
	4, 2, 4, 4, 4, 5, 4, 4, 
	5, 4, 4, 4, 4, 5, 4, 4, 
	5, 4, 4, 4, 4, 4, 4, 5, 
	4, 2, 4, 4, 4, 5, 4, 0, 
	3, 0, 2, 2, 2, 2, 4, 5, 
	4, 4, 4, 4, 4, 4, 4, 4, 
	4, 2, 2, 2, 2, 2, 4, 5, 
	4, 4, 4, 4, 4, 4, 4, 4, 
	4, 4, 4, 4, 4, 4, 4, 4, 
	4, 4, 0
};

static const short _reply_key_offsets[] = {
	0, 0, 5, 9, 11, 14, 15, 17, 
	18, 19, 22, 23, 25, 32, 41, 45, 
	46, 47, 48, 50, 53, 54, 58, 62, 
	64, 67, 68, 71, 75, 77, 78, 79, 
	82, 83, 85, 92, 101, 118, 131, 145, 
	155, 164, 172, 173, 182, 194, 208, 222, 
	230, 231, 240, 241, 243, 243, 250, 254, 
	269, 274, 290
};

static const short _reply_trans_keys[] = {
	36, 42, 43, 45, 58, 45, 48, 49, 
	57, 48, 57, 13, 48, 57, 10, 13, 
	48, 10, 13, 13, 48, 57, 10, 384, 
	639, 1549, 1805, 2061, 384, 524, 526, 639, 
	266, 522, 1549, 1805, 2061, 384, 524, 526, 
	639, 45, 48, 49, 57, 49, 13, 10, 
	13, 48, 13, 48, 57, 10, 5668, 5675, 
	5677, 5690, 5677, 5680, 5681, 5689, 5680, 5689, 
	5645, 5680, 5689, 5642, 5645, 5504, 5759, 5642, 
	5645, 5504, 5759, 5645, 5680, 5642, 5645, 5645, 
	5680, 5689, 5642, 2944, 3199, 4621, 4877, 5133, 
	2944, 3084, 3086, 3199, 2826, 3082, 4621, 4877, 
	5133, 2944, 3084, 3086, 3199, 2861, 2864, 3117, 
	3120, 4621, 4877, 5133, 2865, 2873, 2944, 3084, 
	3086, 3119, 3121, 3129, 3130, 3199, 4621, 4877, 
	5133, 2864, 2873, 2944, 3084, 3086, 3119, 3120, 
	3129, 3130, 3199, 4365, 4621, 4877, 5133, 2864, 
	2873, 2944, 3084, 3086, 3119, 3120, 3129, 3130, 
	3199, 2864, 3120, 4365, 4621, 4877, 5133, 2944, 
	3084, 3086, 3199, 2826, 3082, 4621, 4877, 5133, 
	2944, 3084, 3086, 3199, 4365, 4621, 4877, 5133, 
	2944, 3084, 3086, 3199, 5642, 2826, 3082, 4621, 
	4877, 5133, 2944, 3084, 3086, 3199, 4365, 4621, 
	4877, 5133, 2688, 2828, 2830, 2943, 2944, 3084, 
	3086, 3199, 2826, 3082, 4365, 4621, 4877, 5133, 
	2688, 2828, 2830, 2943, 2944, 3084, 3086, 3199, 
	4365, 4621, 4877, 5133, 2864, 2873, 2944, 3084, 
	3086, 3119, 3120, 3129, 3130, 3199, 2826, 4621, 
	4877, 5133, 2944, 3084, 3086, 3199, 5642, 2826, 
	3082, 4621, 4877, 5133, 2944, 3084, 3086, 3199, 
	13, 10, 13, 1549, 1805, 2061, 384, 524, 
	526, 639, 5668, 5675, 5677, 5690, 2852, 2859, 
	2861, 2874, 3108, 3115, 3117, 3130, 4621, 4877, 
	5133, 2944, 3084, 3086, 3199, 5645, 5668, 5675, 
	5677, 5690, 2852, 2859, 2861, 2874, 3108, 3115, 
	3117, 3130, 4365, 4621, 4877, 5133, 2944, 3084, 
	3086, 3199, 2852, 2859, 2861, 2874, 3108, 3115, 
	3117, 3130, 2944, 3199, 0
};

static const char _reply_single_lengths[] = {
	0, 5, 2, 0, 1, 1, 2, 1, 
	1, 1, 1, 0, 3, 5, 2, 1, 
	1, 1, 2, 1, 1, 4, 2, 0, 
	1, 1, 1, 2, 2, 1, 1, 1, 
	1, 0, 3, 5, 7, 3, 4, 6, 
	5, 4, 1, 5, 4, 6, 4, 4, 
	1, 5, 1, 2, 0, 3, 4, 11, 
	5, 12, 8
};

static const char _reply_range_lengths[] = {
	0, 0, 1, 1, 1, 0, 0, 0, 
	0, 1, 0, 1, 2, 2, 1, 0, 
	0, 0, 0, 1, 0, 0, 1, 1, 
	1, 0, 1, 1, 0, 0, 0, 1, 
	0, 1, 2, 2, 5, 5, 5, 2, 
	2, 2, 0, 2, 4, 4, 5, 2, 
	0, 2, 0, 0, 0, 2, 0, 2, 
	0, 2, 1
};

static const short _reply_index_offsets[] = {
	0, 0, 6, 10, 12, 15, 17, 20, 
	22, 24, 27, 29, 31, 37, 45, 49, 
	51, 53, 55, 58, 61, 63, 68, 72, 
	74, 77, 79, 82, 86, 89, 91, 93, 
	96, 98, 100, 106, 114, 127, 136, 146, 
	155, 163, 170, 172, 180, 189, 200, 210, 
	217, 219, 227, 229, 232, 233, 239, 244, 
	258, 264, 279
};

static const char _reply_indicies[] = {
	0, 2, 3, 3, 3, 1, 4, 5, 
	6, 1, 7, 1, 8, 7, 1, 9, 
	1, 10, 5, 1, 11, 1, 8, 1, 
	12, 13, 1, 14, 1, 15, 1, 15, 
	8, 16, 15, 15, 1, 9, 17, 15, 
	8, 16, 15, 15, 1, 18, 19, 20, 
	1, 21, 1, 22, 1, 23, 1, 22, 
	19, 1, 24, 25, 1, 26, 1, 27, 
	28, 28, 28, 1, 29, 30, 31, 1, 
	32, 1, 33, 32, 1, 34, 1, 35, 
	28, 1, 34, 35, 28, 1, 36, 30, 
	1, 37, 1, 33, 1, 38, 39, 1, 
	40, 1, 41, 1, 41, 33, 42, 41, 
	41, 1, 34, 43, 41, 33, 42, 41, 
	41, 1, 29, 30, 44, 45, 41, 33, 
	42, 31, 41, 41, 46, 41, 1, 41, 
	33, 42, 32, 41, 41, 47, 41, 1, 
	33, 42, 33, 42, 32, 41, 41, 47, 
	41, 1, 30, 45, 36, 48, 49, 50, 
	41, 41, 1, 37, 51, 41, 33, 42, 
	41, 41, 1, 33, 42, 33, 42, 41, 
	41, 1, 52, 1, 52, 53, 41, 33, 
	42, 41, 41, 1, 35, 55, 35, 55, 
	28, 28, 54, 54, 1, 34, 43, 35, 
	55, 35, 55, 28, 28, 54, 54, 1, 
	38, 57, 58, 59, 39, 41, 41, 56, 
	41, 1, 40, 41, 33, 42, 41, 41, 
	1, 60, 1, 60, 43, 41, 33, 42, 
	41, 41, 1, 61, 3, 62, 61, 3, 
	1, 15, 8, 16, 15, 15, 1, 27, 
	28, 28, 28, 1, 27, 28, 28, 28, 
	63, 54, 54, 54, 41, 33, 42, 41, 
	41, 1, 33, 27, 28, 28, 28, 1, 
	27, 28, 28, 28, 63, 54, 54, 54, 
	33, 42, 33, 42, 41, 41, 1, 27, 
	28, 28, 28, 63, 54, 54, 54, 41, 
	1, 0
};

static const char _reply_trans_targs[] = {
	2, 0, 14, 50, 3, 6, 9, 4, 
	5, 52, 7, 8, 10, 9, 11, 12, 
	13, 53, 15, 18, 19, 16, 17, 52, 
	20, 19, 21, 22, 26, 23, 28, 31, 
	24, 25, 54, 27, 29, 30, 32, 31, 
	33, 34, 35, 55, 37, 39, 46, 38, 
	40, 42, 43, 41, 56, 57, 44, 45, 
	46, 47, 48, 49, 58, 51, 52, 36
};

static const char _reply_trans_actions[] = {
	0, 0, 0, 0, 0, 0, 1, 0, 
	0, 2, 0, 0, 0, 3, 0, 0, 
	0, 2, 0, 0, 4, 0, 0, 5, 
	0, 6, 7, 0, 0, 0, 0, 1, 
	0, 0, 8, 0, 0, 0, 0, 3, 
	0, 0, 0, 8, 0, 0, 1, 0, 
	0, 0, 0, 0, 8, 8, 0, 0, 
	3, 0, 0, 0, 8, 0, 9, 0
};

static const int reply_start = 1;
static const int reply_error = 0;


njt_int_t
njt_http_redis2_process_reply(njt_http_redis2_ctx_t *ctx, ssize_t bytes)
{
    njt_buf_t                *b;
    njt_http_upstream_t      *u;
    njt_str_t                 buf;
    njt_flag_t                done;
    njt_chain_t              *cl = NULL;
    njt_chain_t             **ll = NULL;

    int                       cs;
    signed char              *p;
    signed char              *orig_p;
    ssize_t                   orig_len;
    signed char              *pe;

    u = ctx->request->upstream;
    b = &u->buffer;

    orig_p = (signed char *) b->last;
    orig_len = bytes;

    while (ctx->query_count) {
        done = 0;

        if (ctx->state == NJT_ERROR) {
            dd("init the state machine");
			cs = reply_start;
            ctx->state = cs;
        } else {
            cs = ctx->state;
            dd("resumed the old state %d", cs);
        }

        p  = (signed char *) b->last;
        pe = (signed char *) b->last + bytes;

        dd("response body: %.*s", (int) bytes, p);

	{
	int _klen;
	const short *_keys;
	int _trans;
	short _widec;

	if ( p == pe )
		goto _test_eof;
	if ( cs == 0 )
		goto _out;
_resume:
	_widec = (*p);
	_klen = _reply_cond_lengths[cs];
	_keys = _reply_cond_keys + (_reply_cond_offsets[cs]*2);
	if ( _klen > 0 ) {
		const short *_lower = _keys;
		const short *_mid;
		const short *_upper = _keys + (_klen<<1) - 2;
		while (1) {
			if ( _upper < _lower )
				break;

			_mid = _lower + (((_upper-_lower) >> 1) & ~1);
			if ( _widec < _mid[0] )
				_upper = _mid - 2;
			else if ( _widec > _mid[1] )
				_lower = _mid + 2;
			else {
				switch ( _reply_cond_spaces[_reply_cond_offsets[cs] + ((_mid - _keys)>>1)] ) {
	case 0: {
		_widec = (short)(128 + ((*p) - -128));
		if ( 

#if 0
        fprintf(stderr, "test chunk len: %d < %d\n",
            (int) ctx->chunk_bytes_read, (int) ctx->chunk_size),
#endif
        ctx->chunk_bytes_read++ < ctx->chunk_size
     ) _widec += 256;
		break;
	}
	case 1: {
		_widec = (short)(640 + ((*p) - -128));
		if ( 

#if 0
        fprintf(stderr,
            "check_data_complete: chunk bytes read: %d, chunk size: %d\n",
            (int) ctx->chunk_bytes_read, (int) ctx->chunk_size),
#endif
        ctx->chunk_bytes_read == ctx->chunk_size + 1
     ) _widec += 256;
		break;
	}
	case 2: {
		_widec = (short)(5248 + ((*p) - -128));
		if ( 

#if 0
        fprintf(stderr, "test chunk count: %d < %d\n",
            (int) ctx->chunks_read, (int) ctx->chunk_count),
#endif
        ctx->chunks_read < ctx->chunk_count
     ) _widec += 256;
		break;
	}
	case 3: {
		_widec = (short)(1152 + ((*p) - -128));
		if ( 

#if 0
        fprintf(stderr, "test chunk len: %d < %d\n",
            (int) ctx->chunk_bytes_read, (int) ctx->chunk_size),
#endif
        ctx->chunk_bytes_read++ < ctx->chunk_size
     ) _widec += 256;
		if ( 

#if 0
        fprintf(stderr,
            "check_data_complete: chunk bytes read: %d, chunk size: %d\n",
            (int) ctx->chunk_bytes_read, (int) ctx->chunk_size),
#endif
        ctx->chunk_bytes_read == ctx->chunk_size + 1
     ) _widec += 512;
		break;
	}
	case 4: {
		_widec = (short)(2176 + ((*p) - -128));
		if ( 

#if 0
        fprintf(stderr, "test chunk len: %d < %d\n",
            (int) ctx->chunk_bytes_read, (int) ctx->chunk_size),
#endif
        ctx->chunk_bytes_read++ < ctx->chunk_size
     ) _widec += 256;
		if ( 

#if 0
        fprintf(stderr, "test chunk count: %d < %d\n",
            (int) ctx->chunks_read, (int) ctx->chunk_count),
#endif
        ctx->chunks_read < ctx->chunk_count
     ) _widec += 512;
		break;
	}
	case 5: {
		_widec = (short)(3200 + ((*p) - -128));
		if ( 

#if 0
        fprintf(stderr, "test chunk len: %d < %d\n",
            (int) ctx->chunk_bytes_read, (int) ctx->chunk_size),
#endif
        ctx->chunk_bytes_read++ < ctx->chunk_size
     ) _widec += 256;
		if ( 

#if 0
        fprintf(stderr,
            "check_data_complete: chunk bytes read: %d, chunk size: %d\n",
            (int) ctx->chunk_bytes_read, (int) ctx->chunk_size),
#endif
        ctx->chunk_bytes_read == ctx->chunk_size + 1
     ) _widec += 512;
		if ( 

#if 0
        fprintf(stderr, "test chunk count: %d < %d\n",
            (int) ctx->chunks_read, (int) ctx->chunk_count),
#endif
        ctx->chunks_read < ctx->chunk_count
     ) _widec += 1024;
		break;
	}
				}
				break;
			}
		}
	}

	_keys = _reply_trans_keys + _reply_key_offsets[cs];
	_trans = _reply_index_offsets[cs];

	_klen = _reply_single_lengths[cs];
	if ( _klen > 0 ) {
		const short *_lower = _keys;
		const short *_mid;
		const short *_upper = _keys + _klen - 1;
		while (1) {
			if ( _upper < _lower )
				break;

			_mid = _lower + ((_upper-_lower) >> 1);
			if ( _widec < *_mid )
				_upper = _mid - 1;
			else if ( _widec > *_mid )
				_lower = _mid + 1;
			else {
				_trans += (unsigned int)(_mid - _keys);
				goto _match;
			}
		}
		_keys += _klen;
		_trans += _klen;
	}

	_klen = _reply_range_lengths[cs];
	if ( _klen > 0 ) {
		const short *_lower = _keys;
		const short *_mid;
		const short *_upper = _keys + (_klen<<1) - 2;
		while (1) {
			if ( _upper < _lower )
				break;

			_mid = _lower + (((_upper-_lower) >> 1) & ~1);
			if ( _widec < _mid[0] )
				_upper = _mid - 2;
			else if ( _widec > _mid[1] )
				_lower = _mid + 2;
			else {
				_trans += (unsigned int)((_mid - _keys)>>1);
				goto _match;
			}
		}
		_trans += _klen;
	}

_match:
	_trans = _reply_indicies[_trans];
	cs = _reply_trans_targs[_trans];

	if ( _reply_trans_actions[_trans] == 0 )
		goto _again;

	switch ( _reply_trans_actions[_trans] ) {
	case 9:
	{
        dd("done!");
        done = 1;
    }
	break;
	case 3:
	{
        ctx->chunk_size *= 10;
        ctx->chunk_size += *p - '0';
        dd("read chunk size: %d", (int) ctx->chunk_size);
    }
	break;
	case 7:
	{
        dd("start reading bulk");
        ctx->chunks_read = 0;
    }
	break;
	case 6:
	{
        ctx->chunk_count *= 10;
        ctx->chunk_count += *p - '0';
        dd("chunk count: %d", (int) ctx->chunk_count);
    }
	break;
	case 5:
	{
        dd("finalize multi bulks");

        if (ctx->chunks_read == ctx->chunk_count) {
            dd("done multi bunlk reading!");
            done = 1;
        }
    }
	break;
	case 1:
	{
        dd("start reading chunk size");
        ctx->chunk_bytes_read = 0;
        ctx->chunk_size = 0;
    }
	{
        ctx->chunk_size *= 10;
        ctx->chunk_size += *p - '0';
        dd("read chunk size: %d", (int) ctx->chunk_size);
    }
	break;
	case 2:
	{
        ctx->chunks_read++;
        dd("have read chunk %d, %.*s", (int) ctx->chunks_read,
            (int) (p - (signed char *) b->last), (signed char *) b->last);
    }
	{
        dd("done!");
        done = 1;
    }
	break;
	case 8:
	{
        ctx->chunks_read++;
        dd("have read chunk %d, %.*s", (int) ctx->chunks_read,
            (int) (p - (signed char *) b->last), (signed char *) b->last);
    }
	{
        dd("finalize multi bulks");

        if (ctx->chunks_read == ctx->chunk_count) {
            dd("done multi bunlk reading!");
            done = 1;
        }
    }
	break;
	case 4:
	{
        dd("start reading bulk count");
        ctx->chunk_count = 0;
    }
	{
        ctx->chunk_count *= 10;
        ctx->chunk_count += *p - '0';
        dd("chunk count: %d", (int) ctx->chunk_count);
    }
	break;
	}

_again:
	if ( cs == 0 )
		goto _out;
	if ( ++p != pe )
		goto _resume;
	_test_eof: {}
	_out: {}
	}


        dd("state after exec: %d, done: %d, %.*s", cs, (int) done,
            (int) (bytes - ((u_char *) p - b->last)), p);

        ctx->state = cs;

        if (!done && cs == reply_error) {
            if (cl) {
                cl->buf->last = cl->buf->pos;
                cl = NULL;
                *ll = NULL;
            }

            buf.data = b->pos;
            buf.len = b->last - b->pos + bytes;

            njt_log_error(NJT_LOG_ERR, ctx->request->connection->log, 0,
                "Redis server returned invalid response near pos %z in "
                "\"%V\"",
                    (ssize_t) ((u_char *) p - b->pos), &buf);

            u->length = 0;

            return NJT_HTTP_INTERNAL_SERVER_ERROR;
        }

        if (cl == NULL) {
            for (cl = u->out_bufs, ll = &u->out_bufs; cl; cl = cl->next) {
                ll = &cl->next;
            }

            cl = njt_chain_get_free_buf(ctx->request->pool, &u->free_bufs);
            if (cl == NULL) {
                u->length = 0;
                return NJT_ERROR;
            }

            cl->buf->flush = 1;
            cl->buf->memory = 1;

            *ll = cl;

            dd("response body: %.*s", (int) bytes, p);

            cl->buf->pos = b->last;
            cl->buf->last = (u_char *) p;
            cl->buf->tag = u->output.tag;

        } else {
            cl->buf->last = (u_char *) p;
        }

        bytes -= (ssize_t) ((u_char *) p - b->last);
        b->last = (u_char *) p;

        if (done) {
            dd("response parser done");

            ctx->query_count--;

            if (ctx->query_count == 0) {
                if (cs == reply_error) {
                    buf.data = (u_char *) p;
                    buf.len = orig_p - p + orig_len;

                    njt_log_error(NJT_LOG_WARN, ctx->request->connection->log,
                        0, "Redis server returned extra bytes: \"%V\" (len %z)",
                        &buf, buf.len);

#if 0
                    if (cl) {
                        cl->buf->last = cl->buf->pos;
                        cl = NULL;
                        *ll = NULL;
                    }

                    u->length = 0;

                    return NJT_HTTP_INTERNAL_SERVER_ERROR;
#endif

                } else {
                    u->keepalive = 1;
                }

                u->length = 0;

                break;

            } else {
                ctx->state = NJT_ERROR;
                /* continue */
            }

        } else {
            /* need more data */
            break;
        }
    }

    return NJT_OK;
}
