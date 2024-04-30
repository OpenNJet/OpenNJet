local lor = require("lor.index")
local cjson = require("cjson")
local util = require("api_gateway.utils.util")
local config = require("api_gateway.config.config")
local lorUtil = require("lor.lib.utils.utils")
local http = require("resty.http")

local deployRouter = lor:Router()
local APPS_FOLDER= njt.config.prefix() .."apps"

local RETURN_CODE = {
    SUCCESS = 0,
    WRONG_POST_DATA = 10,
    BASE_PATH_NOT_CORRECT = 20,
    FILE_NOT_EXISTS = 30,
    FILE_NOT_IN_TGZ = 40,
    LOCATION_ADD_ERR =50, 
}

local function extractAppPkg(appFile)
    -- right now, only tgz is supported
    return os.execute("tar xzf " ..appFile .. " -C ".. APPS_FOLDER )
end

local function addLocationForApp(server_name, base_path, app_type)
    -- right now , only lua app is supported
    if string.lower(app_type) ~= "lua" then
        return false, "only lua app_type is supported"
    end

    local location_body = "content_by_lua_file " .. APPS_FOLDER .. base_path .. "/main.lua;"

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
        
        if not loc_resp then
          return false, "unable to call /dyn_loc "..  "err :" .. tostring(err)
        end

    return true, ""
end

local function deployApp(req, res, next)
    local retObj={}

    local inputObj = nil
    local ok, inputObj = pcall(cjson.decode, req.body_raw)
    if not ok then
        retObj.code = RETURN_CODE.WRONG_POST_DATA
        retObj.msg = "post data is not a valid json"
        inputObj = nil
    end

    if inputObj then
        local server_name= inputObj.server_name or ""
        local base_path= inputObj.base_path
        local app_type = inputObj.app_type
        local uploaded_file = njt.config.prefix().."data/"..inputObj.uploaded_file
        -- check if file is in data/ folder
        if not util.fileExists(uploaded_file) then        
            retObj.code = RETURN_CODE.FILE_NOT_EXISTS
            retObj.msg = "File "..inputObj.uploaded_file.." is not found"
            goto DEPLOY_FINISH
        end

        if not lorUtil.start_with(base_path, "/") then
            retObj.code = RETURN_CODE.BASE_PATH_NOT_CORRECT
            retObj.msg = "base_path should start with /"
            goto DEPLOY_FINISH
        end

        local rc = extractAppPkg(uploaded_file)
        if not rc or type(rc) ~= "number" or rc ~= 0 then
            retObj.code = RETURN_CODE.FILE_NOT_IN_TGZ
            retObj.msg = "File is not in .tar.gz format"
            goto DEPLOY_FINISH
        end
        
        local ok, msg = addLocationForApp(server_name, base_path, app_type)
        if not ok then
            retObj.code = RETURN_CODE.LOCATION_ADD_ERR
            retObj.msg = msg
            goto DEPLOY_FINISH
        end

        retObj.code = RETURN_CODE.SUCCESS
        retObj.msg = "success"
    end

    ::DEPLOY_FINISH::
    res:json(retObj, true)
end


deployRouter:post("/app", deployApp)

return deployRouter