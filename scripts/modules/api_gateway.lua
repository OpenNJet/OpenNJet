local _M = {}

function _M.init_master()
    -- init modules
    local ok, res

    ok, res = pcall(require, "configuration")
    if not ok then
        error("require failed: " .. tostring(res))
    else
        configuration = res
        configuration.prohibited_localhost_port = '8080'
    end

    ok, res = pcall(require, "balancer")
    if not ok then
        error("require failed: " .. tostring(res))
    else
        balancer = res
    end

    ok, res = pcall(require, "health_check")
    if not ok then
        error("require failed: " .. tostring(res))
    else
        health_check = res
    end

    local process = require("njt.process")
    local ok, err = process.enable_privileged_agent(10240)
    if not ok then
        error("enable privileged agent failed")
    end
end

function _M.init_worker()
    if require("njt.process").type() ~= "privileged agent" then
        balancer.init_worker()
    else
        local configuration_data = njt.shared.configuration_data
        local kv = require("njt.kv")
        local rc, backends = kv.db_kv_get("__LUA_UPSTREAM_BACKENDS")
        if rc == 0 then
            local now = njt.now()
            configuration_data:set("backends", backends)
            configuration_data:set("hc_backends", backends)
            configuration_data:set("raw_backends_last_synced_at", now)
            configuration_data:set("raw_hc_backends_last_synced_at", now)
        end
        health_check.init_worker(configuration, njt.shared.configuration_data)
    end
end

function _M.auth()
    local lor = require("lor.index")
    local app = lor()
    local authRouter = require("api_gateway.routes.auth")
    app:conf("view enable", false)
    app:use("/api_gateway/auth", authRouter())
    -- 错误处理中间件
    app:erroruse(function(err, req, res, next)
        njt.log(njt.ERR, err)

        if req:is_found() ~= true then
            res:status(404):send("404! sorry, not found. ")
        else
            res:status(500):send("internal error")
        end
    end)
    app:run()
end

function _M.main()
    local lor = require("lor.index")
    local router = require("api_gateway.router")
    local app = lor()
    app:conf("view enable", false)
    router(app)
    -- 错误处理中间件
    app:erroruse(function(err, req, res, next)
        njt.log(njt.ERR, err)

        if req:is_found() ~= true then
            res:status(404):send("404! sorry, not found. ")
        else
            res:status(500):send("internal error")
        end
    end)
    app:run()
end

return _M
