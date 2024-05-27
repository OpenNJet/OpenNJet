local http_checker = require("health_check.http")
local tcp_checker = require("health_check.tcp")
local configuration 
local configuration_data 
local cjson = require("cjson.safe")
cjson.encode_escape_forward_slash(false)

local _M = {}

local hc_func = {
    http = http_checker.check,
    tcp = tcp_checker.check
}
local hc_results = {}
local backends = {}
local backends_last_synced_at = 0

local HEALTH_CHECK_INTERVAL = 1 

-- Save copied tables in `copies`, indexed by original table.
local function deepcopy(orig, copies)
    copies = copies or {}
    local orig_type = type(orig)
    local copy
    if orig_type == "table" then
        if copies[orig] then
            copy = copies[orig]
        else
            copy = {}
            copies[orig] = copy
            for orig_key, orig_value in next, orig, nil do
                copy[deepcopy(orig_key, copies)] = deepcopy(orig_value, copies)
            end
            setmetatable(copy, deepcopy(getmetatable(orig), copies))
        end
    else -- number, string, boolean, etc
        copy = orig
    end
    return copy
end

local function syn_backends()
    local backends_data = configuration_data:get("hc_backends")
    njt.log(njt.DEBUG, "health check get_backends_data:", backends_data)
    if not backends_data then
        backends = {}
        njt.log(njt.DEBUG, "backends_data is nil")
        return
    end

    local new_backends, err = cjson.decode(backends_data)
    if not new_backends then
        njt.log(njt.ERR, "could not parse backends data: ", err)
        return
    end

    backends = new_backends
    hc_results = {}
    backends_last_synced_at = njt.time()
end

local function starts_with(str, start)
    return str:sub(1, #start) == start
end

local function ends_with(str, ending)
    return ending == "" or str:sub(-(#ending)) == ending
end

local function time_str_to_number(interval)
    if ends_with(interval, "s") then
        return tonumber(string.sub(interval, 1, #interval - 1)) or HEALTH_CHECK_INTERVAL
    end
    return HEALTH_CHECK_INTERVAL
end

local function build_url_params_from_conf(hc_conf, ep)
    local uri = ""
    local check_param = {}

    local check_type = hc_conf.type or "http"

    if check_type == "tcp" then
        uri = ep.address .. ":" .. (hc_conf.port and hc_conf.port or ep.port)
        check_param = {
            type = "tcp",
            timeout = hc_conf.timeout or 1,
            uri = uri,
            dataSend = "",
            bodyMatch = hc_conf.bodyMatch or ""
        }
    end
    if check_type == "http" then
        uri = hc_conf.schema or "http"
        uri = uri .. "://" .. ep.address .. ":" .. (hc_conf.port and hc_conf.port or ep.port) .. (hc_conf.path or "/")

        check_param = {
            type = check_type,
            timeout = hc_conf.timeout or 1,
            uri = uri,
            statusMatch = hc_conf.statusMatch or "200-399",
            bodyMatch = hc_conf.bodyMatch or "",
            headers = hc_conf.headers
        }
    end
    return uri, check_param
end

local function do_health_check()
    local raw_hc_backends_last_synced_at = configuration_data:get("raw_hc_backends_last_synced_at") or 1
    if raw_hc_backends_last_synced_at > backends_last_synced_at then
        syn_backends()
    end

    local hc_threads = {}
    local task_tracking = {}

    local conf_sync_time_before_hc = configuration.get_raw_backends_last_synced_at()

    local time_before_hc = njt.time()
    local total_hc_peers = 0
    for _, backend in ipairs(backends) do
        local backend_name = backend.name
        local endpoints = backend.endpoints
        local hc_conf = backend.healthCheck

        if hc_conf and hc_conf.interval then
            local hc_result =
                hc_results[backend_name] or
                {
                    check_time = 0,
                    ep_status_changes = false
                }
            local interval = hc_conf.interval
            if njt.time() - hc_result.check_time >= interval then
                hc_result.check_time = njt.time()
                hc_results[backend_name] = hc_result

                for _, ep in ipairs(endpoints) do
                    local check_type = hc_conf.type or "http"
                    local checker = hc_func[check_type]

                    if checker then
                        local uri
                        local check_param
                        uri, check_param = build_url_params_from_conf(hc_conf, ep)

                        local task_id = njt.thread.spawn(checker, check_param)
                        if task_id then
                            local task = {
                                task_id = task_id,
                                backend_name = backend_name,
                                uri = uri,
                                hc_conf = hc_conf
                            }
                            table.insert(task_tracking, task)
                            total_hc_peers = total_hc_peers + 1
                        end
                    end
                end
            end
        end
    end

    -- wait result and update hc_results
    for _, task in ipairs(task_tracking) do
        local ok, res = njt.thread.wait(task.task_id)
        if ok then
            local backend_name = task.backend_name

            njt.log(njt.INFO, "got backend:" .. backend_name .. " uri:" .. task.uri .. " result: " .. cjson.encode(res))

            local result_ok = res[1]

            local hc_result = hc_results[backend_name]

            -- update result status
            local ep_result =
                hc_result[task.uri] or
                {
                    up = true,
                    succ_count = 0,
                    fail_count = 0
                }

            if result_ok and not ep_result.up then
                ep_result.succ_count = (ep_result.succ_count or 0) + 1
            elseif not result_ok and ep_result.up then
                ep_result.fail_count = (ep_result.fail_count or 0) + 1
            end
            if ep_result.succ_count >= task.hc_conf.passes and not ep_result.up then
                ep_result.up = true
                ep_result.succ_count = 0
                ep_result.fail_count = 0
                hc_result.ep_status_changes = true
            end
            if ep_result.fail_count >= task.hc_conf.fails and ep_result.up then
                ep_result.up = false
                ep_result.succ_count = 0
                ep_result.fail_count = 0
                hc_result.ep_status_changes = true
            end
            hc_result[task.uri] = ep_result
        end
    end
    njt.update_time()
    local total_hc_duration = njt.time() - time_before_hc
    njt.log(
        njt.DEBUG,
        "total hc peers: " ..
            tostring(total_hc_peers) ..
                ", total hc duration: " .. tostring(total_hc_duration) .. ", current njt time:" .. tostring(njt.time())
    )

    -- if there is any backend endpoints status changes, sync balancer
    local backends_after_hc = {}
    local need_sync = false
    for _, backend in ipairs(backends) do
        local backend_name = backend.name
        local hc_result = hc_results[backend_name]
        if hc_result then
            if hc_result.ep_status_changes then
                need_sync = true
            end
            local copied_backend = deepcopy(backend)
            copied_backend.endpoints = {}

            local hc_conf = backend.healthCheck
            for _, ep in ipairs(backend.endpoints) do
                local uri = build_url_params_from_conf(hc_conf, ep)

                if hc_result[uri] and hc_result[uri].up then
                    table.insert(copied_backend.endpoints, ep)
                end
            end
            table.insert(backends_after_hc, copied_backend)
            -- reset endpoint status change flag
            hc_result.ep_status_changes = false
        else
            table.insert(backends_after_hc, backend)
        end
    end

    if need_sync and conf_sync_time_before_hc == configuration.get_raw_backends_last_synced_at() then
        local success, err = configuration_data:set("backends", cjson.encode(backends_after_hc))
        if not success then
            njt.log(njt.ERR, "can't set backends after health cheack")
        end
        local raw_backends_last_synced_at = njt.now()
        success, err = configuration_data:set("raw_backends_last_synced_at", raw_backends_last_synced_at)
        if not success then
            njt.log(njt.ERR, "can't set backends sync time after health cheack")
        end
    end

    njt.log(njt.DEBUG, "hc result: " .. (cjson.encode(hc_results) or ""))
end

function _M.init_worker(conf_lib, conf_data)
    configuration = conf_lib
    configuration_data = conf_data
    ok, err = njt.timer.every(HEALTH_CHECK_INTERVAL, do_health_check)
    if not ok then
        njt.log(njt.ERR, "error when setting up timer.every for health_check init worker: ", err)
    end
end

return _M
