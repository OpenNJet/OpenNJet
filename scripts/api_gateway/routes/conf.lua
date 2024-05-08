local lor = require("lor.index")
local cjson = require("cjson")
local util = require("api_gateway.utils.util")
local config = require("api_gateway.config.config")
local lorUtil = require("lor.lib.utils.utils")
local http = require("resty.http")

local confRouter = lor:Router()
local APPS_FOLDER= njt.config.prefix() .."apps"

local RETURN_CODE = {
    SUCCESS = 0,
    WRONG_POST_DATA = 10,
    BASE_PATH_NOT_CORRECT = 20,
    LOCATION_ADD_ERR =30, 
}


local function addLocationForService(server_name, base_path, upstream_name)
    local body={
        "proxy_next_upstream_tries  10;",
        "proxy_pass http://upstream_balancer;"
     }
    
    table.insert(body,"set $proxy_upstream_name \"".. upstream_name .."\";")

    local location_body = table.concat(body, "\n")

    return util.addLocationForApp(server_name, base_path, location_body)   
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

        if not lorUtil.start_with(base_path, "/") then
            retObj.code = RETURN_CODE.BASE_PATH_NOT_CORRECT
            retObj.msg = "base_path should start with /"
            goto DEPLOY_FINISH
        end
        
        local upstream_name="up".. string.gsub(base_path, "/", "_")

        local ok, msg = addLocationForService(server_name, base_path, upstream_name)
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


confRouter:post("/service", registerService)

return confRouter