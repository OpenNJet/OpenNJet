-- Copyright (C) Yichun Zhang (agentzh)


local ffi = require 'ffi'
local base = require "resty.core.base"
local bit = require "bit"
local subsystem = njt.config.subsystem
require "resty.core.time"  -- for njt.now used by resty.lrucache

if subsystem == 'http' then
    require "resty.core.phase"  -- for njt.get_phase
end

local lrucache = require "resty.lrucache"

local lrucache_get = lrucache.get
local lrucache_set = lrucache.set
local ffi_string = ffi.string
local ffi_gc = ffi.gc
local ffi_copy = ffi.copy
local ffi_cast = ffi.cast
local C = ffi.C
local bor = bit.bor
local band = bit.band
local lshift = bit.lshift
local sub = string.sub
local fmt = string.format
local byte = string.byte
local njt = njt
local type = type
local tostring = tostring
local error = error
local setmetatable = setmetatable
local tonumber = tonumber
local get_string_buf = base.get_string_buf
local get_string_buf_size = base.get_string_buf_size
local new_tab = base.new_tab
local njt_phase = njt.get_phase
local njt_log = njt.log
local njt_NOTICE = njt.NOTICE


local _M = {
    version = base.version
}


njt.re = new_tab(0, 5)


local pcre_ver_fn

if subsystem == 'http' then
    ffi.cdef[[
        const char *njt_http_lua_ffi_pcre_version(void);
    ]]
    pcre_ver_fn = C.njt_http_lua_ffi_pcre_version

elseif subsystem == 'stream' then
    ffi.cdef[[
        const char *njt_stream_lua_ffi_pcre_version(void);
    ]]
    pcre_ver_fn = C.njt_stream_lua_ffi_pcre_version

else
    error("unsupported subsystem: " .. tostring(subsystem))
end

local pcre_ver

if not pcall(function() pcre_ver = ffi_string(pcre_ver_fn()) end) then
    setmetatable(njt.re, {
        __index = function(_, key)
            error("no support for 'njt.re." .. key .. "': OpenResty was " ..
                  "compiled without PCRE support", 2)
        end
    })

    _M.no_pcre = true

    return _M
end


local MAX_ERR_MSG_LEN = 256


local FLAG_COMPILE_ONCE  = 0x01
local FLAG_DFA           = 0x02
local FLAG_JIT           = 0x04
local FLAG_DUPNAMES      = 0x08
local FLAG_NO_UTF8_CHECK = 0x10


local PCRE_CASELESS          = 0x0000001
local PCRE_MULTILINE         = 0x0000002
local PCRE_DOTALL            = 0x0000004
local PCRE_EXTENDED          = 0x0000008
local PCRE_ANCHORED          = 0x0000010
local PCRE_UTF8              = 0x0000800
local PCRE_DUPNAMES          = 0x0080000
local PCRE_JAVASCRIPT_COMPAT = 0x2000000


-- PCRE2_ERROR_NOMATCH uses the same value
local PCRE_ERROR_NOMATCH = -1


local regex_match_cache
local regex_sub_func_cache = new_tab(0, 4)
local regex_sub_str_cache = new_tab(0, 4)
local max_regex_cache_size
local regex_cache_size = 0
local script_engine
local njt_lua_ffi_max_regex_cache_size
local njt_lua_ffi_destroy_regex
local njt_lua_ffi_compile_regex
local njt_lua_ffi_exec_regex
local njt_lua_ffi_create_script_engine
local njt_lua_ffi_destroy_script_engine
local njt_lua_ffi_init_script_engine
local njt_lua_ffi_compile_replace_template
local njt_lua_ffi_script_eval_len
local njt_lua_ffi_script_eval_data

-- PCRE 8.43 on macOS introduced the MAP_JIT option when creating the memory
-- region used to store JIT compiled code, which does not survive across
-- `fork()`, causing further usage of PCRE JIT compiler to segfault in worker
-- processes.
--
-- This flag prevents any regex used in the init phase to be JIT compiled or
-- cached when running under macOS, even if the user requests so. Caching is
-- thus disabled to prevent further calls of same regex in worker to have poor
-- performance.
--
-- TODO: improve this workaround when PCRE allows for unspecifying the MAP_JIT
-- option.
local no_jit_in_init
local pcre_ver_num

local maj, min = string.match(pcre_ver, "^(%d+)%.(%d+)")
if maj and min then
    pcre_ver_num = tonumber(maj .. min)
end

if jit.os == "OSX" then
    if pcre_ver_num == nil then
        -- assume this version is faulty as well
        no_jit_in_init = true

    -- PCRE2 is also subject to this issue on macOS
    elseif pcre_ver_num >= 843 then
        no_jit_in_init = true
    end
end

-- pcre2
if pcre_ver_num > 845 then
    -- option
    PCRE_CASELESS          = 0x00000008
    PCRE_MULTILINE         = 0x00000400
    PCRE_DOTALL            = 0x00000020
    PCRE_EXTENDED          = 0x00000080
    PCRE_ANCHORED          = 0x80000000
    PCRE_UTF8              = 0x00080000
    PCRE_DUPNAMES          = 0x00000040
    -- In the pcre2, The PCRE_JAVASCRIPT_COMPAT option has been split into
    -- independent functional options PCRE2_ALT_BSUX, PCRE2_ALLOW_EMPTY_CLASS,
    -- and PCRE2_MATCH_UNSET_BACKREF.
    local PCRE2_ALT_BSUX            = 0x00000002
    local PCRE2_ALLOW_EMPTY_CLASS   = 0x00000001
    local PCRE2_MATCH_UNSET_BACKREF = 0x00000200
    PCRE_JAVASCRIPT_COMPAT = bor(PCRE2_ALT_BSUX, PCRE2_ALLOW_EMPTY_CLASS)
    PCRE_JAVASCRIPT_COMPAT = bor(PCRE2_MATCH_UNSET_BACKREF,
                                 PCRE_JAVASCRIPT_COMPAT)
end

if subsystem == 'http' then
    ffi.cdef[[

    typedef struct {
        njt_str_t                   value;
        void                       *lengths;
        void                       *values;
    } njt_http_lua_complex_value_t;

    typedef struct {
        void                         *pool;
        unsigned char                *name_table;
        int                           name_count;
        int                           name_entry_size;

        int                           ncaptures;
        int                          *captures;

        void                         *regex;
        void                         *regex_sd;

        njt_http_lua_complex_value_t *replace;

        const char                   *pattern;
    } njt_http_lua_regex_t;

    njt_http_lua_regex_t *
        njt_http_lua_ffi_compile_regex(const unsigned char *pat,
            size_t pat_len, int flags,
            int pcre_opts, unsigned char *errstr,
            size_t errstr_size);

    int njt_http_lua_ffi_exec_regex(njt_http_lua_regex_t *re, int flags,
        const unsigned char *s, size_t len, int pos);

    void njt_http_lua_ffi_destroy_regex(njt_http_lua_regex_t *re);

    int njt_http_lua_ffi_compile_replace_template(njt_http_lua_regex_t *re,
                                                  const unsigned char
                                                  *replace_data,
                                                  size_t replace_len);

    struct njt_http_lua_script_engine_s;
    typedef struct njt_http_lua_script_engine_s  *njt_http_lua_script_engine_t;

    njt_http_lua_script_engine_t *njt_http_lua_ffi_create_script_engine(void);

    void njt_http_lua_ffi_init_script_engine(njt_http_lua_script_engine_t *e,
                                             const unsigned char *subj,
                                             njt_http_lua_regex_t *compiled,
                                             int count);

    void njt_http_lua_ffi_destroy_script_engine(
        njt_http_lua_script_engine_t *e);

    size_t njt_http_lua_ffi_script_eval_len(njt_http_lua_script_engine_t *e,
                                            njt_http_lua_complex_value_t *cv);

    size_t njt_http_lua_ffi_script_eval_data(njt_http_lua_script_engine_t *e,
                                             njt_http_lua_complex_value_t *cv,
                                             unsigned char *dst);

    uint32_t njt_http_lua_ffi_max_regex_cache_size(void);
    ]]

    njt_lua_ffi_max_regex_cache_size = C.njt_http_lua_ffi_max_regex_cache_size
    njt_lua_ffi_destroy_regex = C.njt_http_lua_ffi_destroy_regex
    njt_lua_ffi_compile_regex = C.njt_http_lua_ffi_compile_regex
    njt_lua_ffi_exec_regex = C.njt_http_lua_ffi_exec_regex
    njt_lua_ffi_create_script_engine = C.njt_http_lua_ffi_create_script_engine
    njt_lua_ffi_init_script_engine = C.njt_http_lua_ffi_init_script_engine
    njt_lua_ffi_destroy_script_engine = C.njt_http_lua_ffi_destroy_script_engine
    njt_lua_ffi_compile_replace_template =
        C.njt_http_lua_ffi_compile_replace_template
    njt_lua_ffi_script_eval_len = C.njt_http_lua_ffi_script_eval_len
    njt_lua_ffi_script_eval_data = C.njt_http_lua_ffi_script_eval_data

elseif subsystem == 'stream' then
    ffi.cdef[[

    typedef struct {
        njt_str_t                   value;
        void                       *lengths;
        void                       *values;
    } njt_stream_lua_complex_value_t;

    typedef struct {
        void                            *pool;
        unsigned char                   *name_table;
        int                              name_count;
        int                              name_entry_size;

        int                              ncaptures;
        int                             *captures;

        void                            *regex;
        void                            *regex_sd;

        njt_stream_lua_complex_value_t  *replace;

        const char                      *pattern;
    } njt_stream_lua_regex_t;

    njt_stream_lua_regex_t *
        njt_stream_lua_ffi_compile_regex(const unsigned char *pat,
            size_t pat_len, int flags,
            int pcre_opts, unsigned char *errstr,
            size_t errstr_size);

    int njt_stream_lua_ffi_exec_regex(njt_stream_lua_regex_t *re, int flags,
        const unsigned char *s, size_t len, int pos);

    void njt_stream_lua_ffi_destroy_regex(njt_stream_lua_regex_t *re);

    int njt_stream_lua_ffi_compile_replace_template(njt_stream_lua_regex_t *re,
                                                    const unsigned char
                                                    *replace_data,
                                                    size_t replace_len);

    struct njt_stream_lua_script_engine_s;
    typedef struct njt_stream_lua_script_engine_s
        *njt_stream_lua_script_engine_t;

    njt_stream_lua_script_engine_t *
        njt_stream_lua_ffi_create_script_engine(void);

    void njt_stream_lua_ffi_init_script_engine(
        njt_stream_lua_script_engine_t *e, const unsigned char *subj,
        njt_stream_lua_regex_t *compiled, int count);

    void njt_stream_lua_ffi_destroy_script_engine(
        njt_stream_lua_script_engine_t *e);

    size_t njt_stream_lua_ffi_script_eval_len(
        njt_stream_lua_script_engine_t *e, njt_stream_lua_complex_value_t *cv);

    size_t njt_stream_lua_ffi_script_eval_data(
        njt_stream_lua_script_engine_t *e, njt_stream_lua_complex_value_t *cv,
        unsigned char *dst);

    uint32_t njt_stream_lua_ffi_max_regex_cache_size(void);
    ]]

    njt_lua_ffi_max_regex_cache_size = C.njt_stream_lua_ffi_max_regex_cache_size
    njt_lua_ffi_destroy_regex = C.njt_stream_lua_ffi_destroy_regex
    njt_lua_ffi_compile_regex = C.njt_stream_lua_ffi_compile_regex
    njt_lua_ffi_exec_regex = C.njt_stream_lua_ffi_exec_regex
    njt_lua_ffi_create_script_engine = C.njt_stream_lua_ffi_create_script_engine
    njt_lua_ffi_init_script_engine = C.njt_stream_lua_ffi_init_script_engine
    njt_lua_ffi_destroy_script_engine =
        C.njt_stream_lua_ffi_destroy_script_engine
    njt_lua_ffi_compile_replace_template =
        C.njt_stream_lua_ffi_compile_replace_template
    njt_lua_ffi_script_eval_len = C.njt_stream_lua_ffi_script_eval_len
    njt_lua_ffi_script_eval_data = C.njt_stream_lua_ffi_script_eval_data
end


local c_str_type = ffi.typeof("const char *")

local cached_re_opts = new_tab(0, 4)

local buf_grow_ratio = 2


function _M.set_buf_grow_ratio(ratio)
    buf_grow_ratio = ratio
end


local function get_max_regex_cache_size()
    if max_regex_cache_size then
        return max_regex_cache_size
    end
    max_regex_cache_size = njt_lua_ffi_max_regex_cache_size()
    return max_regex_cache_size
end


local regex_cache_is_empty = true


function _M.is_regex_cache_empty()
    return regex_cache_is_empty
end


local function lrucache_set_wrapper(...)
    regex_cache_is_empty = false
    lrucache_set(...)
end


local parse_regex_opts = function (opts)
    local t = cached_re_opts[opts]
    if t then
        return t[1], t[2]
    end

    local flags = 0
    local pcre_opts = 0
    local len = #opts

    for i = 1, len do
        local opt = byte(opts, i)
        if opt == byte("o") then
            flags = bor(flags, FLAG_COMPILE_ONCE)

        elseif opt == byte("j") then
            flags = bor(flags, FLAG_JIT)

        elseif opt == byte("i") then
            pcre_opts = bor(pcre_opts, PCRE_CASELESS)

        elseif opt == byte("s") then
            pcre_opts = bor(pcre_opts, PCRE_DOTALL)

        elseif opt == byte("m") then
            pcre_opts = bor(pcre_opts, PCRE_MULTILINE)

        elseif opt == byte("u") then
            pcre_opts = bor(pcre_opts, PCRE_UTF8)

        elseif opt == byte("U") then
            pcre_opts = bor(pcre_opts, PCRE_UTF8)
            flags = bor(flags, FLAG_NO_UTF8_CHECK)

        elseif opt == byte("x") then
            pcre_opts = bor(pcre_opts, PCRE_EXTENDED)

        elseif opt == byte("d") then
            flags = bor(flags, FLAG_DFA)

        elseif opt == byte("a") then
            pcre_opts = bor(pcre_opts, PCRE_ANCHORED)

        elseif opt == byte("D") then
            pcre_opts = bor(pcre_opts, PCRE_DUPNAMES)
            flags = bor(flags, FLAG_DUPNAMES)

        elseif opt == byte("J") then
            pcre_opts = bor(pcre_opts, PCRE_JAVASCRIPT_COMPAT)

        else
            error(fmt('unknown flag "%s" (flags "%s")', sub(opts, i, i), opts),
                  3)
        end
    end

    cached_re_opts[opts] = {flags, pcre_opts}
    return flags, pcre_opts
end


if no_jit_in_init then
    local parse_regex_opts_ = parse_regex_opts

    parse_regex_opts = function (opts)
        if njt_phase() ~= "init" then
            -- past init_by_lua* phase now
            parse_regex_opts = parse_regex_opts_
            return parse_regex_opts(opts)
        end

        local t = cached_re_opts[opts]
        if t then
            return t[1], t[2]
        end

        local flags = 0
        local pcre_opts = 0
        local len = #opts

        for i = 1, len do
            local opt = byte(opts, i)
            if opt == byte("o") then
                njt_log(njt_NOTICE, "regex compilation cache disabled in init ",
                                    "phase under macOS")

            elseif opt == byte("j") then
                njt_log(njt_NOTICE, "regex compilation disabled in init ",
                                    "phase under macOS")

            elseif opt == byte("i") then
                pcre_opts = bor(pcre_opts, PCRE_CASELESS)

            elseif opt == byte("s") then
                pcre_opts = bor(pcre_opts, PCRE_DOTALL)

            elseif opt == byte("m") then
                pcre_opts = bor(pcre_opts, PCRE_MULTILINE)

            elseif opt == byte("u") then
                pcre_opts = bor(pcre_opts, PCRE_UTF8)

            elseif opt == byte("U") then
                pcre_opts = bor(pcre_opts, PCRE_UTF8)
                flags = bor(flags, FLAG_NO_UTF8_CHECK)

            elseif opt == byte("x") then
                pcre_opts = bor(pcre_opts, PCRE_EXTENDED)

            elseif opt == byte("d") then
                flags = bor(flags, FLAG_DFA)

            elseif opt == byte("a") then
                pcre_opts = bor(pcre_opts, PCRE_ANCHORED)

            elseif opt == byte("D") then
                pcre_opts = bor(pcre_opts, PCRE_DUPNAMES)
                flags = bor(flags, FLAG_DUPNAMES)

            elseif opt == byte("J") then
                pcre_opts = bor(pcre_opts, PCRE_JAVASCRIPT_COMPAT)

            else
                error(fmt('unknown flag "%s" (flags "%s")', sub(opts, i, i),
                          opts), 3)
            end
        end

        cached_re_opts[opts] = {flags, pcre_opts}
        return flags, pcre_opts
    end
end


local function collect_named_captures(compiled, flags, res)
    local name_count = compiled.name_count
    local name_table = compiled.name_table
    local entry_size = compiled.name_entry_size

    local ind = 0
    local dup_names = (band(flags, FLAG_DUPNAMES) ~= 0)
    for i = 1, name_count do
        local n = bor(lshift(name_table[ind], 8), name_table[ind + 1])
        -- njt.say("n = ", n)
        local name = ffi_string(name_table + ind + 2)
        local cap = res[n]
        if dup_names then
            -- unmatched captures (false) are not collected
            if cap then
                local old = res[name]
                if old then
                    old[#old + 1] = cap
                else
                    res[name] = {cap}
                end
            end
        else
            res[name] = cap
        end

        ind = ind + entry_size
    end
end


local function collect_captures(compiled, rc, subj, flags, res)
    local cap = compiled.captures
    local ncap = compiled.ncaptures
    local name_count = compiled.name_count

    if not res then
        res = new_tab(ncap, name_count)
    end

    local i = 0
    local n = 0
    while i <= ncap do
        if i > rc then
            res[i] = false
        else
            local from = cap[n]
            if from >= 0 then
                local to = cap[n + 1]
                res[i] = sub(subj, from + 1, to)
            else
                res[i] = false
            end
        end
        i = i + 1
        n = n + 2
    end

    if name_count > 0 then
        collect_named_captures(compiled, flags, res)
    end

    return res
end


_M.collect_captures = collect_captures


local function destroy_compiled_regex(compiled)
    njt_lua_ffi_destroy_regex(ffi_gc(compiled, nil))
end


_M.destroy_compiled_regex = destroy_compiled_regex


local function re_match_compile(regex, opts)
    local flags = 0
    local pcre_opts = 0

    if opts then
        flags, pcre_opts = parse_regex_opts(opts)
    else
        opts = ""
    end

    local compiled, key
    local compile_once = (band(flags, FLAG_COMPILE_ONCE) == 1)

    -- FIXME: better put this in the outer scope when fixing the njt.re API's
    -- compatibility in the init_by_lua* context.
    if not regex_match_cache then
        local sz = get_max_regex_cache_size()
        if sz <= 0 then
            compile_once = false
        else
            regex_match_cache = lrucache.new(sz)
        end
    end

    if compile_once then
        key = regex .. '\0' .. opts
        compiled = lrucache_get(regex_match_cache, key)
    end

    -- compile the regex

    if compiled == nil then
        -- print("compiled regex not found, compiling regex...")
        local errbuf = get_string_buf(MAX_ERR_MSG_LEN)

        compiled = njt_lua_ffi_compile_regex(regex, #regex, flags,
                                             pcre_opts, errbuf,
                                             MAX_ERR_MSG_LEN)

        if compiled == nil then
            return nil, ffi_string(errbuf)
        end

        ffi_gc(compiled, njt_lua_ffi_destroy_regex)

        -- print("ncaptures: ", compiled.ncaptures)

        if compile_once then
            -- print("inserting compiled regex into cache")
            lrucache_set_wrapper(regex_match_cache, key, compiled)
        end
    end

    return compiled, compile_once, flags
end


_M.re_match_compile = re_match_compile


local function re_match_helper(subj, regex, opts, ctx, want_caps, res, nth)
    -- we need to cast this to strings to avoid exceptions when they are
    -- something else.
    subj  = tostring(subj)

    local compiled, compile_once, flags = re_match_compile(regex, opts)
    if compiled == nil then
        -- compiled_once holds the error string
        if not want_caps then
            return nil, nil, compile_once
        end
        return nil, compile_once
    end

    -- exec the compiled regex

    local rc
    do
        local pos
        if ctx then
            pos = ctx.pos
            if not pos or pos <= 0 then
                pos = 0
            else
                pos = pos - 1
            end

        else
            pos = 0
        end

        rc = njt_lua_ffi_exec_regex(compiled, flags, subj, #subj, pos)
    end

    if rc == PCRE_ERROR_NOMATCH then
        if not compile_once then
            destroy_compiled_regex(compiled)
        end
        return nil
    end

    if rc < 0 then
        if not compile_once then
            destroy_compiled_regex(compiled)
        end
        if not want_caps then
            return nil, nil, "pcre_exec() failed: " .. rc
        end
        return nil, "pcre_exec() failed: " .. rc
    end

    if rc == 0 then
        if band(flags, FLAG_DFA) == 0 then
            if not want_caps then
                return nil, nil, "capture size too small"
            end
            return nil, "capture size too small"
        end

        rc = 1
    end

    -- print("cap 0: ", compiled.captures[0])
    -- print("cap 1: ", compiled.captures[1])

    if ctx then
        ctx.pos = compiled.captures[1] + 1
    end

    if not want_caps then
        if not nth or nth < 0 then
            nth = 0
        end

        if nth > compiled.ncaptures then
            return nil, nil, "nth out of bound"
        end

        if nth >= rc then
            return nil, nil
        end

        local from = compiled.captures[nth * 2] + 1
        local to = compiled.captures[nth * 2 + 1]

        if from < 0 or to < 0 then
            return nil, nil
        end

        return from, to
    end

    res = collect_captures(compiled, rc, subj, flags, res)

    if not compile_once then
        destroy_compiled_regex(compiled)
    end

    return res
end


function njt.re.match(subj, regex, opts, ctx, res)
    return re_match_helper(subj, regex, opts, ctx, true, res)
end


function njt.re.find(subj, regex, opts, ctx, nth)
    return re_match_helper(subj, regex, opts, ctx, false, nil, nth)
end


do
    local function destroy_re_gmatch_iterator(iterator)
        if not iterator._compile_once then
            destroy_compiled_regex(iterator._compiled)
        end
        iterator._compiled = nil
        iterator._pos = nil
        iterator._subj = nil
    end


    local function iterate_re_gmatch(self)
        local compiled = self._compiled
        local subj = self._subj
        local subj_len = self._subj_len
        local flags = self._flags
        local pos = self._pos

        if not pos then
            -- The iterator is exhausted.
            return nil
        end

        local rc = njt_lua_ffi_exec_regex(compiled, flags, subj, subj_len, pos)

        if rc == PCRE_ERROR_NOMATCH then
            destroy_re_gmatch_iterator(self)
            return nil
        end

        if rc < 0 then
            destroy_re_gmatch_iterator(self)
            return nil, "pcre_exec() failed: " .. rc
        end

        if rc == 0 then
            if band(flags, FLAG_DFA) == 0 then
                destroy_re_gmatch_iterator(self)
                return nil, "capture size too small"
            end

            rc = 1
        end

        local cp_pos = tonumber(compiled.captures[1])
        if cp_pos == compiled.captures[0] then
            cp_pos = cp_pos + 1
            if cp_pos > subj_len then
                local res = collect_captures(compiled, rc, subj, flags)
                destroy_re_gmatch_iterator(self)
                return res
            end
        end
        self._pos = cp_pos
        return collect_captures(compiled, rc, subj, flags)
    end


    local re_gmatch_iterator_mt = { __call = iterate_re_gmatch }

    function njt.re.gmatch(subj, regex, opts)
        subj  = tostring(subj)

        local compiled, compile_once, flags = re_match_compile(regex, opts)
        if compiled == nil then
            -- compiled_once holds the error string
            return nil, compile_once
        end

        local re_gmatch_iterator = {
            _compiled = compiled,
            _compile_once = compile_once,
            _subj = subj,
            _subj_len = #subj,
            _flags = flags,
            _pos = 0,
        }

        return setmetatable(re_gmatch_iterator, re_gmatch_iterator_mt)
    end
end  -- do


local function new_script_engine(subj, compiled, count)
    if not script_engine then
        script_engine = njt_lua_ffi_create_script_engine()
        if script_engine == nil then
            return nil
        end
        ffi_gc(script_engine, njt_lua_ffi_destroy_script_engine)
    end

    njt_lua_ffi_init_script_engine(script_engine, subj, compiled, count)
    return script_engine
end


local function check_buf_size(buf, buf_size, pos, len, new_len, must_alloc)
    if new_len > buf_size then
        buf_size = buf_size * buf_grow_ratio
        if buf_size < new_len then
            buf_size = new_len
        end
        local new_buf = get_string_buf(buf_size, must_alloc)
        ffi_copy(new_buf, buf, len)
        buf = new_buf
        pos = buf + len
    end
    return buf, buf_size, pos, new_len
end


_M.check_buf_size = check_buf_size


local function re_sub_compile(regex, opts, replace, func)
    local flags = 0
    local pcre_opts = 0

    if opts then
        flags, pcre_opts = parse_regex_opts(opts)
    else
        opts = ""
    end

    local compiled
    local compile_once = (band(flags, FLAG_COMPILE_ONCE) == 1)
    if compile_once then
        if func then
            local subcache = regex_sub_func_cache[opts]
            if subcache then
                -- print("cache hit!")
                compiled = subcache[regex]
            end

        else
            local subcache = regex_sub_str_cache[opts]
            if subcache then
                local subsubcache = subcache[regex]
                if subsubcache then
                    -- print("cache hit!")
                    compiled = subsubcache[replace]
                end
            end
        end
    end

    -- compile the regex

    if compiled == nil then
        -- print("compiled regex not found, compiling regex...")
        local errbuf = get_string_buf(MAX_ERR_MSG_LEN)

        compiled = njt_lua_ffi_compile_regex(regex, #regex, flags, pcre_opts,
                                             errbuf, MAX_ERR_MSG_LEN)

        if compiled == nil then
            return nil, ffi_string(errbuf)
        end

        ffi_gc(compiled, njt_lua_ffi_destroy_regex)

        if func == nil then
            local rc =
                njt_lua_ffi_compile_replace_template(compiled, replace,
                                                     #replace)
            if rc ~= 0 then
                if not compile_once then
                    destroy_compiled_regex(compiled)
                end
                return nil, "failed to compile the replacement template"
            end
        end

        -- print("ncaptures: ", compiled.ncaptures)

        if compile_once then
            if regex_cache_size < get_max_regex_cache_size() then
                -- print("inserting compiled regex into cache")
                if func then
                    local subcache = regex_sub_func_cache[opts]
                    if not subcache then
                        regex_sub_func_cache[opts] = {[regex] = compiled}

                    else
                        subcache[regex] = compiled
                    end

                else
                    local subcache = regex_sub_str_cache[opts]
                    if not subcache then
                        regex_sub_str_cache[opts] =
                            {[regex] = {[replace] = compiled}}

                    else
                        local subsubcache = subcache[regex]
                        if not subsubcache then
                            subcache[regex] = {[replace] = compiled}

                        else
                            subsubcache[replace] = compiled
                        end
                    end
                end

                regex_cache_size = regex_cache_size + 1
            else
                compile_once = false
            end
        end
    end

    return compiled, compile_once, flags
end


_M.re_sub_compile = re_sub_compile


local function re_sub_func_helper(subj, regex, replace, opts, global)
    local compiled, compile_once, flags =
                                    re_sub_compile(regex, opts, nil, replace)
    if not compiled then
        -- error string is in compile_once
        return nil, nil, compile_once
    end

    -- exec the compiled regex

    subj = tostring(subj)
    local subj_len = #subj
    local count = 0
    local pos = 0
    local cp_pos = 0

    local dst_buf_size = get_string_buf_size()
    -- Note: we have to always allocate the string buffer because
    -- the user might call whatever resty.core's API functions recursively
    -- in the user callback function.
    local dst_buf = get_string_buf(dst_buf_size, true)
    local dst_pos = dst_buf
    local dst_len = 0

    while true do
        local rc = njt_lua_ffi_exec_regex(compiled, flags, subj, subj_len, pos)
        if rc == PCRE_ERROR_NOMATCH then
            break
        end

        if rc < 0 then
            if not compile_once then
                destroy_compiled_regex(compiled)
            end
            return nil, nil, "pcre_exec() failed: " .. rc
        end

        if rc == 0 then
            if band(flags, FLAG_DFA) == 0 then
                if not compile_once then
                    destroy_compiled_regex(compiled)
                end
                return nil, nil, "capture size too small"
            end

            rc = 1
        end

        count = count + 1
        local prefix_len = compiled.captures[0] - cp_pos

        local res = collect_captures(compiled, rc, subj, flags)

        local piece = tostring(replace(res))
        local piece_len = #piece

        local new_dst_len = dst_len + prefix_len + piece_len
        dst_buf, dst_buf_size, dst_pos, dst_len =
            check_buf_size(dst_buf, dst_buf_size, dst_pos, dst_len,
                           new_dst_len, true)

        if prefix_len > 0 then
            ffi_copy(dst_pos, ffi_cast(c_str_type, subj) + cp_pos,
                     prefix_len)
            dst_pos = dst_pos + prefix_len
        end

        if piece_len > 0 then
            ffi_copy(dst_pos, piece, piece_len)
            dst_pos = dst_pos + piece_len
        end

        cp_pos = compiled.captures[1]
        pos = cp_pos
        if pos == compiled.captures[0] then
            pos = pos + 1
            if pos > subj_len then
                break
            end
        end

        if not global then
            break
        end
    end

    if not compile_once then
        destroy_compiled_regex(compiled)
    end

    if count > 0 then
        if cp_pos < subj_len then
            local suffix_len = subj_len - cp_pos

            local new_dst_len = dst_len + suffix_len
            local _
            dst_buf, _, dst_pos, dst_len =
                check_buf_size(dst_buf, dst_buf_size, dst_pos, dst_len,
                               new_dst_len, true)

            ffi_copy(dst_pos, ffi_cast(c_str_type, subj) + cp_pos,
                     suffix_len)
        end
        return ffi_string(dst_buf, dst_len), count
    end

    return subj, 0
end


local function re_sub_str_helper(subj, regex, replace, opts, global)
    local compiled, compile_once, flags =
                                    re_sub_compile(regex, opts, replace, nil)
    if not compiled then
        -- error string is in compile_once
        return nil, nil, compile_once
    end

    -- exec the compiled regex

    subj = tostring(subj)
    local subj_len = #subj
    local count = 0
    local pos = 0
    local cp_pos = 0

    local dst_buf_size = get_string_buf_size()
    local dst_buf = get_string_buf(dst_buf_size)
    local dst_pos = dst_buf
    local dst_len = 0

    while true do
        local rc = njt_lua_ffi_exec_regex(compiled, flags, subj, subj_len, pos)
        if rc == PCRE_ERROR_NOMATCH then
            break
        end

        if rc < 0 then
            if not compile_once then
                destroy_compiled_regex(compiled)
            end
            return nil, nil, "pcre_exec() failed: " .. rc
        end

        if rc == 0 then
            if band(flags, FLAG_DFA) == 0 then
                if not compile_once then
                    destroy_compiled_regex(compiled)
                end
                return nil, nil, "capture size too small"
            end

            rc = 1
        end

        count = count + 1
        local prefix_len = compiled.captures[0] - cp_pos

        local cv = compiled.replace
        if cv.lengths ~= nil then
            local e = new_script_engine(subj, compiled, rc)
            if e == nil then
                return nil, nil, "failed to create script engine"
            end

            local bit_len = njt_lua_ffi_script_eval_len(e, cv)
            local new_dst_len = dst_len + prefix_len + bit_len
            dst_buf, dst_buf_size, dst_pos, dst_len =
                check_buf_size(dst_buf, dst_buf_size, dst_pos, dst_len,
                               new_dst_len)

            if prefix_len > 0 then
                ffi_copy(dst_pos, ffi_cast(c_str_type, subj) + cp_pos,
                         prefix_len)
                dst_pos = dst_pos + prefix_len
            end

            if bit_len > 0 then
                njt_lua_ffi_script_eval_data(e, cv, dst_pos)
                dst_pos = dst_pos + bit_len
            end

        else
            local bit_len = cv.value.len

            dst_buf, dst_buf_size, dst_pos, dst_len =
                check_buf_size(dst_buf, dst_buf_size, dst_pos, dst_len,
                               dst_len + prefix_len + bit_len)

            if prefix_len > 0 then
                ffi_copy(dst_pos, ffi_cast(c_str_type, subj) + cp_pos,
                         prefix_len)
                dst_pos = dst_pos + prefix_len
            end

            if bit_len > 0 then
                ffi_copy(dst_pos, cv.value.data, bit_len)
                dst_pos = dst_pos + bit_len
            end
        end

        cp_pos = compiled.captures[1]
        pos = cp_pos
        if pos == compiled.captures[0] then
            pos = pos + 1
            if pos > subj_len then
                break
            end
        end

        if not global then
            break
        end
    end

    if not compile_once then
        destroy_compiled_regex(compiled)
    end

    if count > 0 then
        if cp_pos < subj_len then
            local suffix_len = subj_len - cp_pos

            local new_dst_len = dst_len + suffix_len
            local _
            dst_buf, _, dst_pos, dst_len =
                check_buf_size(dst_buf, dst_buf_size, dst_pos, dst_len,
                               new_dst_len)

            ffi_copy(dst_pos, ffi_cast(c_str_type, subj) + cp_pos,
                     suffix_len)
        end
        return ffi_string(dst_buf, dst_len), count
    end

    return subj, 0
end


local function re_sub_helper(subj, regex, replace, opts, global)
    local repl_type = type(replace)
    if repl_type == "function" then
        return re_sub_func_helper(subj, regex, replace, opts, global)
    end

    if repl_type ~= "string" then
        replace = tostring(replace)
    end

    return re_sub_str_helper(subj, regex, replace, opts, global)
end


function njt.re.sub(subj, regex, replace, opts)
    return re_sub_helper(subj, regex, replace, opts, false)
end


function njt.re.gsub(subj, regex, replace, opts)
    return re_sub_helper(subj, regex, replace, opts, true)
end


return _M
