local lor = require("lor.index")
local cjson = require("cjson")
local util = require("api_gateway.utils.util")
local config = require("api_gateway.config.config")
local lorUtil = require("lor.lib.utils.utils")
local http = require("resty.http")
local njetApi = require("api_gateway.service.njet")

local deployRouter = lor:Router()
local APPS_FOLDER= njt.config.prefix() .."apps"

local RETURN_CODE = {
    SUCCESS = 0,
    WRONG_POST_DATA = 10,
    BASE_PATH_NOT_CORRECT = 20,
    FILE_NOT_EXISTS = 30,
    FILE_NOT_IN_TGZ = 40,
    LOCATION_ADD_ERR = 50, 
    LOCATION_DEL_ERR = 60, 
}

local function delAppFolder(base_path)
    -- when delete app, base_path contain only top directory
    local path= string.gsub(base_path,"/","")  
    if #path == 0 then
        return 0
    end
    return os.execute("rm -rf  " .. APPS_FOLDER .. "/".. path )
end

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

    return njetApi.addLocationForApp(server_name, base_path, location_body)
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

local function delApp(req, res, next)
    local retObj={}
    local inputObj = nil
    local ok, inputObj = pcall(cjson.decode, req.body_raw)
    if not ok then
        retObj.code = RETURN_CODE.WRONG_POST_DATA
        retObj.msg = "post data is not a valid json"
        goto DELAPP_FINISH
    end

    if inputObj then
        local server_name= inputObj.server_name or ""
        local base_path= inputObj.base_path
        if not lorUtil.start_with(base_path, "/") then
            retObj.code = RETURN_CODE.BASE_PATH_NOT_CORRECT
            retObj.msg = "base_path should start with /"
            goto DELAPP_FINISH
        end

        -- delete apps/base_path
        local rc = delAppFolder(base_path)
        if not rc or type(rc) ~= "number" or rc ~= 0 then
            njt.log(njt.ERR, "can't remove ".. base_path.. " from apps folder")
        end
        --remove location 
        local ok, msg= njetApi.delLocationForApp(server_name, base_path)  
        if not ok then
            retObj.code = RETURN_CODE.LOCATION_DEL_ERR
            retObj.msg = msg
            goto DELAPP_FINISH
        end 

        retObj.code = RETURN_CODE.SUCCESS
        retObj.msg = "success"
    end

    ::DELAPP_FINISH::
    res:json(retObj, true)
end

deployRouter:post("/app", deployApp)
deployRouter:delete("/app", delApp)

return deployRouter