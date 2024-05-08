local cjson = require("cjson")
local config = require("api_gateway.config.config")
local http = require("resty.http")

local _M = {}
local HMAC_KEY = "xItp/m24fxz49pnm1wy"

function _M.checkEmail(email)
    if not email or type(email) ~= "string" then
        return false
    end

    if (email:match("[A-Za-z0-9%.%%%+%-]+@[A-Za-z0-9%.%%%+%-]+%.%w%w%w?%w?")) then
        return true
    else
        return false
    end
end

function _M.checkMobile(mobile)
    if type(mobile) == "number" and #tostring(mobile) == 11 then
        return true
    end

    if type(mobile) == "string" and #mobile == 11 and tonumber(mobile) then
        return true
    end
    return false
end

function _M.encryptPassword(msg)
    return njt.encode_base64(njt.hmac_sha1(HMAC_KEY, msg))
end

function _M.isArray(t)
    if type(t) ~= "table" then
        return false
    end
    local i = 0
    for _ in pairs(t) do
        i = i + 1
        if t[i] == nil then
            return false
        end
    end
    return true
end

function _M.fileExists(name)
    local f=io.open(name,"r")
    if f~=nil then io.close(f) return true else return false end
 end

local function read_from_file(file_name)
    local f = io.open(file_name, "r")
    if not f then 
      return nil
    end
    local string = f:read("*all")
    f:close()
    return string
end

function _M.getBodyData()
    njt.req.read_body()
    local req_body = njt.req.get_body_data()
    if not req_body then
       local body_file = njt.req.get_body_file()
       if body_file then
         req_body = read_from_file(body_file)
       end
    end
    return req_body
end

function _M.addLocationForApp(server_name, base_path, location_body)
    local httpc = http.new()
    local ctrl_api_base= config.ctrl_api_base
    local http_log_uri = ctrl_api_base.."/config/http_log"
    local log_resp, err = httpc:request_uri(http_log_uri, {
        method = "GET",
        body = "",
        ssl_verify = false,
      })
      
      if not log_resp then
        return false, "unable to call /config/http_log, "..  "err :" .. tostring(err)
      end
     
      local log_resp_body=log_resp.body 
      local ok, logRespObj=pcall(cjson.decode, log_resp_body)
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
      submitData.addr_port= listens[1]
      submitData.server_name = serverNames[1]
      submitData.locations={}
      table.insert(submitData.locations, {location_name=base_path, location_body=location_body})
      local http_log_uri = ctrl_api_base.."/dyn_loc"
      local loc_resp, err = httpc:request_uri(http_log_uri, {
          method = "POST",
          body = cjson.encode(submitData),
          ssl_verify = false,
        })
        
        if not loc_resp or err then
          return false, "unable to call /dyn_loc "..  "err :" .. tostring(err)
        end

    return true, ""
end

return _M
