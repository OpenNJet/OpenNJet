local lor = require("lor.index")
local cjson = require("cjson")
local util = require("api_gateway.utils.util")
local config = require("api_gateway.config.config")
local lorUtil = require("lor.lib.utils.utils")
local http = require("resty.http")
local njetApi = require("api_gateway.service.njet")

local confRouter = lor:Router()
local APPS_FOLDER= njt.config.prefix() .."apps"
local UPSTREAM_NAME_PREFIX="up"

local RETURN_CODE = {
    SUCCESS = 0,
    WRONG_POST_DATA = 10,
    BASE_PATH_NOT_CORRECT = 20,
    LOCATION_ADD_ERR =30, 
    LOCATION_DEL_ERR = 40, 
    UPSTREAM_UPDATE_ERR = 50, 
    UPSTREAM_QUERY_ERR = 60, 
}

local function delLocationForService(server_name, base_path, upstream)
    local ok, msg= njetApi.delLocationForApp(server_name, base_path)   
    if not ok then
        return false, msg
    end

    return njetApi.delUpstream(upstream)
end

local function addLocationForService(server_name, base_path, upstream)
    local body={
        "proxy_set_header Host $host;",
        "proxy_set_header X-Real-IP $remote_addr;",
        "proxy_http_version 1.1;",
        "proxy_next_upstream_tries 10;",
        "proxy_pass http://upstream_balancer;"
     }
    
    table.insert(body,"set $proxy_upstream_name \"".. upstream.name .."\";")

    local location_body = table.concat(body, "\n")

    local ok, msg= njetApi.addLocationForApp(server_name, base_path, location_body)   
    if not ok then
        return false, msg
    end

    return njetApi.addUpstream(upstream)
end

local function registerService(req, res, next)
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
        local upstream = inputObj.upstream

        if not base_path or not upstream then
            retObj.code = RETURN_CODE.WRONG_POST_DATA
            retObj.msg = "base_path and upstream fields are mandatory"
            goto DEPLOY_FINISH
        end

        if  type(upstream) ~= "table" then
            retObj.code = RETURN_CODE.WRONG_POST_DATA
            retObj.msg = "upstream fields should be an object"
            goto DEPLOY_FINISH
        end

        if not lorUtil.start_with(base_path, "/") then
            retObj.code = RETURN_CODE.BASE_PATH_NOT_CORRECT
            retObj.msg = "base_path should start with /"
            goto DEPLOY_FINISH
        end
        
        local upstream_name=UPSTREAM_NAME_PREFIX .. string.gsub(base_path, "/", "_")

        upstream.name = upstream_name
        local ok, msg = addLocationForService(server_name, base_path, upstream)
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

local function unRegisterService(req, res, next)
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
    
        if not base_path then
            retObj.code = RETURN_CODE.WRONG_POST_DATA
            retObj.msg = "base_path field is mandatory"
            goto UNREG_FINISH
        end

        if not lorUtil.start_with(base_path, "/") then
            retObj.code = RETURN_CODE.BASE_PATH_NOT_CORRECT
            retObj.msg = "base_path should start with /"
            goto UNREG_FINISH
        end
        
        local upstream = {}
        local upstream_name= UPSTREAM_NAME_PREFIX .. string.gsub(base_path, "/", "_")

        upstream.name = upstream_name
        local ok, msg = delLocationForService(server_name, base_path, upstream)
        if not ok then
            retObj.code = RETURN_CODE.LOCATION_DEL_ERR
            retObj.msg = msg
            goto UNREG_FINISH
        end

        retObj.code = RETURN_CODE.SUCCESS
        retObj.msg = "success"
    end

    ::UNREG_FINISH::
    res:json(retObj, true)
end

local function updateService(req, res, next)
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
        local upstream = inputObj.upstream

        if not base_path or not upstream then
            retObj.code = RETURN_CODE.WRONG_POST_DATA
            retObj.msg = "base_path and upstream fields are mandatory"
            goto UPDATE_SRV_FINISH
        end

        if  type(upstream) ~= "table" then
            retObj.code = RETURN_CODE.WRONG_POST_DATA
            retObj.msg = "upstream fields should be an object"
            goto UPDATE_SRV_FINISH
        end

        if not lorUtil.start_with(base_path, "/") then
            retObj.code = RETURN_CODE.BASE_PATH_NOT_CORRECT
            retObj.msg = "base_path should start with /"
            goto UPDATE_SRV_FINISH
        end
        
        local upstream_name=UPSTREAM_NAME_PREFIX .. string.gsub(base_path, "/", "_")

        upstream.name = upstream_name
        local ok, msg =  njetApi.addUpstream(upstream)
        if not ok then
            retObj.code = RETURN_CODE.UPSTREAM_UPDATE_ERR
            retObj.msg = msg
            goto UPDATE_SRV_FINISH
        end

        retObj.code = RETURN_CODE.SUCCESS
        retObj.msg = "success"
    end

    ::UPDATE_SRV_FINISH::
    res:json(retObj, true)
end

local function getUpstreams(req, res, next)
    local retObj={}

    local ok, msg = njetApi.getUpstreams()
    if not ok then
        retObj.code = RETURN_CODE.UPSTREAM_QUERY_ERR
        retObj.msg = msg
    else 
        retObj.code = RETURN_CODE.SUCCESS
        retObj.msg = "success"
        local ok, backendsObj = pcall(cjson.decode, msg)
        if ok then 
            retObj.data = backendsObj
        else 
            retObj.data = msg
        end
    end

    res:json(retObj, true)
end

confRouter:post("/service", registerService)
confRouter:delete("/service", unRegisterService)
confRouter:put("/service", updateService)
confRouter:get("/upstreams", getUpstreams)

return confRouter