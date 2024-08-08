local lor = require("lor.index")
local cjson = require("cjson")
local util = require("api_gateway.utils.util")
local config = require("api_gateway.config.config")
local lorUtil = require("lor.lib.utils.utils")
local http = require("resty.http")
local njetApi = require("api_gateway.service.njet")
local sysConfigDao = require("api_gateway.dao.sys_config")

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
    SYS_CONFIG_UPDATE_ERR = 70, 
    SYS_CONFIG_QUERY_ERR = 80, 
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

local function updateSmtpConfig(req, res, next)
    local retObj={}

    local inputObj = nil
    local ok, inputObj = pcall(cjson.decode, req.body_raw)
    if not ok then
        retObj.code = RETURN_CODE.WRONG_POST_DATA
        retObj.msg = "post data is not a valid json"
        inputObj = nil
    end

    if inputObj then
        local username = inputObj.username 
        local password = inputObj.password 
        local confs ={}

        if not inputObj.host then
            retObj.code = RETURN_CODE.WRONG_POST_DATA
            retObj.msg = "host field is mandatory"
            goto UPDATE_SMTP_FINISH
        else 
            table.insert(confs, {config_key="smtp.host", config_value=tostring(inputObj.host), config_type="string"})
        end
        if inputObj.port then
            if not tonumber(inputObj.port) then 
                retObj.code = RETURN_CODE.WRONG_POST_DATA
                retObj.msg = "port field should be a number"
                goto UPDATE_SMTP_FINISH
            else
                table.insert(confs, {config_key="smtp.port", config_value=tostring(inputObj.port), config_type="number"})
            end
        end 
        if inputObj.starttls then 
            table.insert(confs, {config_key="smtp.starttls", config_value=tostring(inputObj.starttls), config_type="boolean"})
        end
        if inputObj.username then 
            table.insert(confs, {config_key="smtp.username", config_value=tostring(inputObj.username), config_type="string"})
        end
        if inputObj.password then 
            -- 如果lua搜索路径中有ssh_remote_mod.so，则密码进行加密后再保存到数据库中
            local ok, encrypt_lib=pcall(require, "ssh_remote_mod")
            if ok then 
                local rc, encrypted_passwd=encrypt_lib.encrypt_msg(inputObj.password)
                if rc == 0 then
                   table.insert(confs, {config_key="smtp.password", config_value=encrypted_passwd, config_type="password"})
                else
                   table.insert(confs, {config_key="smtp.password", config_value=tostring(inputObj.password), config_type="string"})
                end
            else 
                table.insert(confs, {config_key="smtp.password", config_value=tostring(inputObj.password), config_type="string"})
            end
        end
        if inputObj.email_from then 
            table.insert(confs, {config_key="email_from", config_value=tostring(inputObj.email_from), config_type="string"})
        end

        local ok, msg = sysConfigDao.updateSysConfig(confs)
        if not ok then
            retObj.code = RETURN_CODE.SYS_CONFIG_UPDATE_ERR
            retObj.msg = msg -- second parameter is error msg when error occur 
        else
            config.load_from_db()
            retObj.code = RETURN_CODE.SUCCESS
            retObj.msg = "success"
            retObj.data = msg
        end
    end

    ::UPDATE_SMTP_FINISH::
    res:json(retObj, true)
end

local function getSmtpConfig(req, res, next)
    local retObj={}
    retObj.code=0
    retObj.msg="success"
    retObj.data = {}
    retObj.data.email_from=config.email_from
    for k, v in pairs(config.smtp) do 
        retObj.data[k] = v
    end
    res:json(retObj, true)
end

local function updateSysConfig(req, res, next)
    local retObj={}

    local inputObj = nil
    local ok, inputObj = pcall(cjson.decode, req.body_raw)
    if not ok then
        retObj.code = RETURN_CODE.WRONG_POST_DATA
        retObj.msg = "post data is not a valid json"
        inputObj = nil
    end

    if inputObj then
        if not util.isArray(inputObj) then
            retObj.code = RETURN_CODE.WRONG_POST_DATA
            retObj.msg = "post data should be an array"
            goto UPDATE_SYSCONFIG_FINISH
        end
        local confs ={}
        for _, conf in ipairs(inputObj) do 
            if conf.config_key and conf.config_value and conf.config_type then
               table.insert(confs, {config_key= tostring(conf.config_key), config_value=tostring(conf.config_value), config_type=tostring(conf.config_type)})
            end
        end
 
        local ok, msg = sysConfigDao.updateSysConfig(confs)
        if not ok then
            retObj.code = RETURN_CODE.SYS_CONFIG_UPDATE_ERR
            retObj.msg = msg -- second parameter is error msg when error occur 
        else
            config.load_from_db()
            retObj.code = RETURN_CODE.SUCCESS
            retObj.msg = "success"
            retObj.data = msg
        end
    end

    ::UPDATE_SYSCONFIG_FINISH::
    res:json(retObj, true)
end

local function getSysConfig(req, res, next)
    local retObj={}
    
    local config_key = req.params.key
    local ok, obj = sysConfigDao.getSysConfigByKey(config_key)
    if not ok then
        retObj.code = RETURN_CODE.SYS_CONFIG_QUERY_ERR
        retObj.msg = obj -- second parameter is error msg when error occur 
    else
        retObj.code = RETURN_CODE.SUCCESS
        retObj.msg = "success"
        retObj.data = obj
    end

    res:json(retObj, false)
end

confRouter:post("/service", registerService)
confRouter:delete("/service", unRegisterService)
confRouter:put("/service", updateService)
confRouter:get("/upstreams", getUpstreams)
confRouter:get("/smtp", getSmtpConfig)
confRouter:post("/smtp", updateSmtpConfig)
confRouter:get("/sysconfig/:key", getSysConfig)
confRouter:post("/sysconfig", updateSysConfig)

return confRouter