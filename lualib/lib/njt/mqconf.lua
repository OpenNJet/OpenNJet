local _M = {}

local ffi = require("ffi")

ffi.cdef [[
    typedef intptr_t        njt_int_t;
    typedef uintptr_t       njt_uint_t;
    typedef long            time_t;
    typedef unsigned int (*helper_check_cmd_fp)(void *ctx);

    typedef struct {
        njt_str_t   conf_fn;
        njt_str_t   conf_fullfn;
        helper_check_cmd_fp check_cmd_fp;
        void        *ctx;
        void        *cycle;
        void        *mdb_ctx;   //don't use mdb_ctx in lua, so ignore pointer type
    } helper_param; 
    typedef void (*njt_helper_run_fp)(helper_param param);
    typedef struct {
        helper_param         param;
        njt_helper_run_fp    run_fp;
        void                *handle;
        njt_str_t            file;
        njt_str_t            label;
        njt_int_t            reload;
        time_t               start_time;
        time_t               start_time_bef;
    } njt_helper_ctx;
    typedef struct {
        void        *elts;
        njt_uint_t   nelts;
        size_t       size;
        njt_uint_t   nalloc;
        void         *pool;  //don't use pool in lua, so ignore pointer type
    } njt_array_t;
    typedef struct
    {
        njt_str_t admin_server;
        njt_str_t admin_client;
        njt_str_t cluster_name;
        njt_str_t node_name;
        njt_str_t dyn_conf;
        njt_int_t worker_cnt;
        njt_array_t  helper;
    } njt_mqconf_conf_t;

    njt_mqconf_conf_t *njt_http_sendmsg_get_mqconf();
]]

local function endswith(str, suffix)
    return str:sub(-suffix:len()) == suffix
end

-- return value (ok, {label="xxx", module="xxx",, conf_file="xxx"})
function _M.getAllCopilotConfs()
    local confs = {}

    local mqconf_ptr = ffi.C.njt_http_sendmsg_get_mqconf()
    if mqconf_ptr == ffi.NULL then
        return false, "can't get mqconf from c api"
    else
        local mqconf = ffi.cast("njt_mqconf_conf_t*", mqconf_ptr)
        local helper_array_ptr = ffi.cast("njt_array_t*", mqconf.helper)
        local helper_num = tonumber(helper_array_ptr.nelts)
        local elements = ffi.cast("njt_helper_ctx*", helper_array_ptr.elts)
        -- Loop over the array elements
        for i = 0, helper_num - 1 do
            local e = elements[i]
            local file = ffi.string(e.file.data, e.file.len)
            local label = ffi.string(e.label.data, e.label.len)

            local param = ffi.cast("helper_param*", e.param)
            local fullcf = ffi.string(param.conf_fullfn.data, param.conf_fullfn.len)

            local conf = {
                label = label,
                module = file,
                conf_file = fullcf
            }

            table.insert(confs, conf)
        end
    end

    if #confs > 0 then
        return true, confs
    else
        return false, "can't find helper with module name " .. module_name
    end
end

function _M.getCopilotConfsByModuleName(module_name)
    local confs = {}

    local ok, confs = _M.getAllCopilotConfs()
    if not ok then
        return ok, confs
    end

    local mod_name = module_name;
    if not module_name or module_name == "" then
        return false, "invalid module_name"
    end

    if not endswith(mod_name, ".so") then
        mod_name = mod_name .. ".so"
    end

    local filter_confs = {}
    for _, c in ipairs(confs) do
        if endswith(c.module, mod_name) then
            table.insert(filter_confs, c)
        end
    end

    if #filter_confs > 0 then
        return true, filter_confs
    else
        return false, "can't find helper with module name " .. module_name
    end
end

function _M.getCopilotConfsByLabelName(label)
    local confs = {}

    local ok, confs = _M.getAllCopilotConfs()
    if not ok then
        return ok, confs
    end

    local filter_confs = {}
    for _, c in ipairs(confs) do
        if c.label == label then
            table.insert(filter_confs, c)
            break -- helper label should be unique in njet configure file, return first record found
        end
    end

    if #filter_confs > 0 then
        return true, filter_confs
    else
        return false, "can't find helper with module name " .. label
    end
end

return _M
