collectgarbage("collect")
local _ = require("lor.index")
local _ = require("lsqlite3complete")

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
