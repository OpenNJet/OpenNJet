local cjson = require("cjson")
local config = require("api_gateway.config.config")
local http = require("resty.http")

local BACKEND_KV_KEY = "__LUA_UPSTREAM_BACKENDS"

local _M = {}

local function setBackend(backends)
    local configuration_data = njt.parent_shared.configuration_data
    if not configuration_data then
        return false, "can't get shared dict configuration_data"
    end
    local success, err = configuration_data:set("backends", backends)
    if not success then
        njt.log(njt.ERR, "dynamic-configuration: error updating configuration: " .. tostring(err))
        return false, "error occuried set backends into configuration_data"
    end
    -- keep original backends configuration for health check purpose
    local success, err = configuration_data:set("hc_backends", backends)
    if not success then
        njt.log(njt.ERR, "dynamic-configuration: error updating configuration: " .. tostring(err))
        return false, "error occuried set backends into configuration_data"
    end

    njt.update_time()
    local raw_backends_last_synced_at = njt.now()
    success, err = configuration_data:set("raw_backends_last_synced_at", raw_backends_last_synced_at)
    if not success then
        njt.log(njt.ERR,
            "dynamic-configuration: error updating when backends sync, " ..
                "new upstream peers waiting for force syncing: " .. tostring(err))
        return false, "error occuried set backends into configuration_data"
    end
    success, err = configuration_data:set("raw_hc_backends_last_synced_at", raw_backends_last_synced_at)
    if not success then
        njt.log(njt.ERR,
            "dynamic-configuration: error updating when backends sync, " ..
                "new upstream peers waiting for force syncing: " .. tostring(err))
        return false, "error occuried set backends into configuration_data"
    end
    -- set into kv
    local kv = require("njt.kv")
    kv.db_kv_set(BACKEND_KV_KEY, backends)
    return true, "success"
end

function _M.getUpstreams()
    local configuration_data = njt.parent_shared.configuration_data
    if not configuration_data then
        return false, "can't get shared dict configuration_data"
    end
    local backends = configuration_data:get("hc_backends")
    if not backends then
        return false, "can't get upstreams in configuration data"
    end
    return true, backends
end

function _M.addUpstream(upstream)
    local configuration_data = njt.parent_shared.configuration_data
    if not configuration_data then
        return false, "can't get shared dict configuration_data"
    end
    if not upstream or not upstream.name or not upstream.endpoints then
        return false, "upstream data incorrect"
    end
    if not upstream["load-balance"] then
        upstream["load-balance"] = "round_robin"
    end
    local new_backends = {}
    local backends = {}
    local backends_str = configuration_data:get("hc_backends")
    if backends_str then
        local ok, backends_obj = pcall(cjson.decode, backends_str)
        if ok then
            backends = backends_obj
        end
    end

    for _, v in ipairs(backends) do
        if v.name ~= upstream.name then
            table.insert(new_backends, v)
        else
            if v.healthCheck and upstream.keepHealthCheck then
                upstream.healthCheck = v.healthCheck
            end
        end
    end
    -- always add new upstream
    table.insert(new_backends, upstream)

    return setBackend(cjson.encode(new_backends))
end

function _M.delUpstream(upstream)
    local configuration_data = njt.parent_shared.configuration_data
    if not configuration_data then
        return false, "can't get shared dict configuration_data"
    end
    if not upstream or not upstream.name then
        return false, "upstream data incorrect"
    end

    local new_backends = {}
    local backends = {}
    local backends_str = configuration_data:get("hc_backends")
    if not backends_str then
        backends = {}
    else
        local ok, backends_obj = pcall(cjson.decode, backends_str)
        if ok then
            backends = backends_obj
        end
    end

    for _, v in ipairs(backends) do
        if v.name ~= upstream.name then
            table.insert(new_backends, v)
        end
    end
    return setBackend(cjson.encode(new_backends))
end

function _M.delCUpstream(upstream_name)
    local httpc = http.new()
    local ctrl_api_base = config.ctrl_api_base
    -- del upstream 
    local submitData = {}
    submitData.type = "del"
    submitData.upstream_name = upstream_name
    local api_uri = ctrl_api_base .. "/dyn_ups"
    local api_resp, err = httpc:request_uri(api_uri, {
        method = "PUT",
        body = cjson.encode(submitData),
        ssl_verify = false
    })
    if not api_resp or err then
        return false, "unable to call /dyn_ups " .. "err :" .. tostring(err)
    end

    local ok, resp_body = pcall(cjson.decode, api_resp.body)
    njt.log(njt.DEBUG, "req body:" .. tostring(ok) .. "  resp body: " .. cjson.encode(resp_body))

    if ok then
        if resp_body.code and resp_body.code ~= 0 then
            return false, resp_body.msg
        end
    end

    return true, ""
end

function _M.addCUpstream(upstream_name, servers)
    local httpc = http.new()
    local ctrl_api_base = config.ctrl_api_base
    -- del upstream 
    local submitData = {}
    submitData.type = "add"
    submitData.upstream_name = upstream_name
    submitData.upstream_body = "zone " .. upstream_name .. " 10m;\n"
    local api_uri = ctrl_api_base .. "/dyn_ups"
    local api_resp, err = httpc:request_uri(api_uri, {
        method = "POST",
        body = cjson.encode(submitData),
        ssl_verify = false
    })
    if not api_resp or err then
        return false, "unable to call /dyn_ups " .. "err :" .. tostring(err)
    end

    local ok, resp_body = pcall(cjson.decode, api_resp.body)
    njt.log(njt.DEBUG, "req body:" .. tostring(ok) .. "  resp body: " .. cjson.encode(resp_body))

    if ok then
        if resp_body.code and resp_body.code ~= 0 then
            return false, resp_body.msg
        end
    end

    for _, server in ipairs(servers) do
        local submitData = server
        api_uri = ctrl_api_base .. "/upstream_api/http/upstreams/" .. upstream_name .. "/servers/"
        api_resp, err = httpc:request_uri(api_uri, {
            method = "POST",
            body = cjson.encode(submitData),
            ssl_verify = false
        })
        if not api_resp or err then
            njt.log(njt.ERR,
                "unable to call /dyn_ups " .. "err :" .. tostring(err) .. "req_body: " .. cjson.encode(submitData))
        end
        local ok, resp_body = pcall(cjson.decode, api_resp.body)

        if ok then
            if resp_body.code and resp_body.code ~= 0 then
                njt.log(njt.ERR, "req body:" .. tostring(ok) .. "  resp body: " .. cjson.encode(resp_body) ..
                    " req_body: " .. cjson.encode(submitData))
            end
        end
    end

    return true, ""
end

function _M.addVsForApp(server_name)
    local httpc = http.new()
    local ctrl_api_base = config.ctrl_api_base
    local http_log_uri = ctrl_api_base .. "/config/http_log"
    local log_resp, err = httpc:request_uri(http_log_uri, {
        method = "GET",
        body = "",
        ssl_verify = false
    })

    if not log_resp then
        return false, "unable to call /config/http_log, " .. "err :" .. tostring(err)
    end

    local log_resp_body = log_resp.body
    local ok, logRespObj = pcall(cjson.decode, log_resp_body)
    if not ok or not logRespObj then
        return false, "/config/http_log return wrong data"
    end

    if not logRespObj.servers or #logRespObj.servers == 0 then
        return false, "no server found in ctrl return json"
    end

    local listens = logRespObj.servers[1].listens

    -- add vs
    local submitData = {}
    submitData.type = "add"
    submitData.addr_port = listens[1]
    submitData.server_name = server_name
    submitData.server_body = ""

    local http_srv_uri = ctrl_api_base .. "/dyn_srv"
    local srv_resp, err = httpc:request_uri(http_srv_uri, {
        method = "POST",
        body = cjson.encode(submitData),
        ssl_verify = false
    })
    if not srv_resp or err then
        return false, "unable to call /dyn_srv " .. "err :" .. tostring(err)
    end

    local ok, resp_body = pcall(cjson.decode, srv_resp.body)
    njt.log(njt.DEBUG, "req body:" .. tostring(ok) .. "  resp body: " .. cjson.encode(resp_body))

    if ok then
        if resp_body.code and resp_body.code ~= 0 then
            return false, resp_body.msg
        end
    end

    return true, ""
end

function _M.delVsForApp(server_name)
    local httpc = http.new()
    local ctrl_api_base = config.ctrl_api_base
    local http_log_uri = ctrl_api_base .. "/config/http_log"
    local log_resp, err = httpc:request_uri(http_log_uri, {
        method = "GET",
        body = "",
        ssl_verify = false
    })

    if not log_resp then
        return false, "unable to call /config/http_log, " .. "err :" .. tostring(err)
    end

    local log_resp_body = log_resp.body
    local ok, logRespObj = pcall(cjson.decode, log_resp_body)
    if not ok or not logRespObj then
        return false, "/config/http_log return wrong data"
    end

    if not logRespObj.servers or #logRespObj.servers == 0 then
        return false, "no server found in ctrl return json"
    end

    local listens = logRespObj.servers[1].listens

    -- del vs
    local submitData = {}
    submitData.type = "del"
    submitData.addr_port = listens[1]
    submitData.server_name = server_name
    submitData.server_body = ""

    local http_srv_uri = ctrl_api_base .. "/dyn_srv"
    local srv_resp, err = httpc:request_uri(http_srv_uri, {
        method = "PUT",
        body = cjson.encode(submitData),
        ssl_verify = false
    })
    if not srv_resp or err then
        return false, "unable to call /dyn_srv " .. "err :" .. tostring(err)
    end

    local ok, resp_body = pcall(cjson.decode, srv_resp.body)
    njt.log(njt.DEBUG, "req body:" .. tostring(ok) .. "  resp body: " .. cjson.encode(resp_body))

    if ok then
        if resp_body.code and resp_body.code ~= 0 then
            return false, resp_body.msg
        end
    end

    return true, ""
end

function _M.addLocationForApp(server_name, base_path, location_body)
    local httpc = http.new()
    local ctrl_api_base = config.ctrl_api_base
    local http_log_uri = ctrl_api_base .. "/config/http_log"
    local log_resp, err = httpc:request_uri(http_log_uri, {
        method = "GET",
        body = "",
        ssl_verify = false
    })

    if not log_resp then
        return false, "unable to call /config/http_log, " .. "err :" .. tostring(err)
    end

    local log_resp_body = log_resp.body
    local ok, logRespObj = pcall(cjson.decode, log_resp_body)
    if not ok or not logRespObj then
        return false, "/config/http_log return wrong data"
    end

    if not logRespObj.servers or #logRespObj.servers == 0 then
        return false, "no server found in ctrl return json"
    end

    local listens = logRespObj.servers[1].listens
    local serverNames = logRespObj.servers[1].serverNames
    for _, server in ipairs(logRespObj.servers) do
        if server.serverNames[1] == server_name then
            listens = server.listens
            serverNames = server.serverNames
            break
        end
    end

    -- add location 
    local submitData = {}
    submitData.type = "add"
    submitData.addr_port = listens[1]
    submitData.server_name = serverNames[1]
    submitData.locations = {}
    table.insert(submitData.locations, {
        location_name = base_path,
        location_body = location_body
    })
    local http_log_uri = ctrl_api_base .. "/dyn_loc"
    local loc_resp, err = httpc:request_uri(http_log_uri, {
        method = "POST",
        body = cjson.encode(submitData),
        ssl_verify = false
    })
    if not loc_resp or err then
        return false, "unable to call /dyn_loc " .. "err :" .. tostring(err)
    end

    local ok, resp_body = pcall(cjson.decode, loc_resp.body)
    njt.log(njt.DEBUG, "req body:" .. tostring(ok) .. "  resp body: " .. cjson.encode(resp_body))

    if ok then
        if resp_body.code and resp_body.code ~= 0 then
            return false, resp_body.msg
        end
    end

    return true, ""
end

function _M.delLocationForApp(server_name, base_path)
    local httpc = http.new()
    local ctrl_api_base = config.ctrl_api_base
    local http_log_uri = ctrl_api_base .. "/config/http_log"
    local log_resp, err = httpc:request_uri(http_log_uri, {
        method = "GET",
        body = "",
        ssl_verify = false
    })

    if not log_resp then
        return false, "unable to call /config/http_log, " .. "err :" .. tostring(err)
    end

    local log_resp_body = log_resp.body
    local ok, logRespObj = pcall(cjson.decode, log_resp_body)
    if not ok or not logRespObj then
        return false, "/config/http_log return wrong data"
    end

    if not logRespObj.servers or #logRespObj.servers == 0 then
        return false, "no server found in ctrl return json"
    end

    local listens = logRespObj.servers[1].listens
    local serverNames = logRespObj.servers[1].serverNames
    for _, server in ipairs(logRespObj.servers) do
        if server.serverNames[1] == server_name then
            listens = server.listens
            serverNames = server.serverNames
            break
        end
    end

    -- add location 
    local submitData = {}
    submitData.type = "del"
    submitData.addr_port = listens[1]
    submitData.server_name = serverNames[1]
    submitData.location_rule = ""
    submitData.location_name = base_path
    local http_log_uri = ctrl_api_base .. "/dyn_loc"
    local loc_resp, err = httpc:request_uri(http_log_uri, {
        method = "PUT",
        body = cjson.encode(submitData),
        ssl_verify = false
    })
    if not loc_resp or err then
        return false, "unable to call /dyn_loc " .. "err :" .. tostring(err)
    end

    local ok, resp_body = pcall(cjson.decode, loc_resp.body)
    njt.log(njt.DEBUG, "req body:" .. tostring(ok) .. "  resp body: " .. cjson.encode(resp_body))

    if ok then
        if resp_body.code and resp_body.code ~= 0 then
            return false, resp_body.msg
        end
    end

    return true, ""
end

return _M
