local lor = require("lor.index")
local cjson = require("cjson")
local util = require("api_gateway.utils.util")
local config = require("api_gateway.config.config")
local lorUtil = require("lor.lib.utils.utils")
local http = require("resty.http")
local njetApi = require("api_gateway.service.njet")
local deployAppSrv = require("api_gateway.service.deploy_app")
local constValue = require("api_gateway.config.const")

local deployRouter = lor:Router()

local RETURN_CODE = {
    SUCCESS = 0,
    WRONG_POST_DATA = 10,
    APP_DEL_ERR = 20,
    FILE_NOT_EXISTS = 30,
    FILE_WRONG_FORMAT = 40,
    LOCATION_ADD_ERR = 50,
    LOCATION_DEL_ERR = 60,
    CONFIG_SCHEMA_ERR = 70
}

local function delApp(req, res, next)
    local retObj = {}
    local inputObj = nil
    local ok, inputObj = pcall(cjson.decode, req.body_raw)
    if not ok then
        retObj.code = RETURN_CODE.WRONG_POST_DATA
        retObj.msg = "post data is not a valid json"
        goto DELAPP_FINISH
    end

    if inputObj then
        local app_name = inputObj.app_name
        if not app_name or app_name == "" then
            retObj.code = RETURN_CODE.APP_DEL_ERR
            retObj.msg = "app_name is mandatory"
            goto DELAPP_FINISH
        end

        -- delete apps/base_path
        local ok, msg = deployAppSrv.remove_app(app_name)
        if not ok then
            retObj.code = RETURN_CODE.APP_DEL_ERR
            retObj.msg = msg or ""
        else
            retObj.code = RETURN_CODE.SUCCESS
            retObj.msg = "success"
        end
    end

    ::DELAPP_FINISH::
    res:json(retObj, true)
end

local function deployApp(req, res, next)
    local retObj = {}

    local inputObj = nil
    local ok, inputObj = pcall(cjson.decode, req.body_raw)
    if not ok then
        retObj.code = RETURN_CODE.WRONG_POST_DATA
        retObj.msg = "post data is not a valid json"
        inputObj = nil
    end

    if inputObj then
        local upload_dir = njt.config.data_prefix and njt.config.data_prefix() or njt.config.prefix()
        local uploaded_file = upload_dir .. config.uploaded_file_path .. inputObj.uploaded_file
        -- check if file is in data/ folder
        if not util.fileExists(uploaded_file) then
            retObj.code = RETURN_CODE.FILE_NOT_EXISTS
            retObj.msg = "File " .. inputObj.uploaded_file .. " is not found"
            goto DEPLOY_FINISH
        end

        local ok, msg = deployAppSrv.deploy_app_package(uploaded_file)
        if not ok then
            retObj.code = RETURN_CODE.FILE_WRONG_FORMAT
            retObj.msg = msg or "File is not in correct zip format"
            goto DEPLOY_FINISH
        end

        retObj.code = RETURN_CODE.SUCCESS
        retObj.msg = "success"
    end

    ::DEPLOY_FINISH::
    res:json(retObj, true)
end

local function getAppConfigSchema(req, res, next)
    -- Set JSON header
    res:set_header("Content-Type", "application/json")

    -- Get app name from route parameter
    local app_name = req.params.name
    if not app_name then
        njt.log(njt.ERR, "No app name provided in request")
        return res:json({
            code = RETURN_CODE.CONFIG_SCHEMA_ERR,
            msg = "App name is required"
        }, true)
    end

    -- Validate app name (no spaces, consistent with deploy_app_package)
    if string.match(app_name, "%s") then
        njt.log(njt.ERR, "Invalid app name: ", app_name)
        return res:json({
            code = RETURN_CODE.CONFIG_SCHEMA_ERR,
            msg = "App name cannot contain spaces"
        }, true)
    end

    local schema_path = string.format("%s/%s/META-INF/config_schema.json", constValue.APPS_FOLDER, app_name)

    -- Check if file exists
    local file = io.open(schema_path, "r")
    if not file then
        njt.log(njt.ERR, "Schema file not found: ", schema_path)
        return res:json({
            code = RETURN_CODE.CONFIG_SCHEMA_ERR,
            msg = "Schema file not found for app: " .. app_name
        }, true)
    end

    -- Read file content
    local content = file:read("*a")
    file:close()

    -- Verify content is valid JSON (optional, for safety)
    local success, _ = pcall(cjson.decode, content)
    if not success then
        njt.log(njt.ERR, "Schema file is not valid JSON: ", schema_path)
        return res:json({
            code = RETURN_CODE.CONFIG_SCHEMA_ERR,
            msg = "Schema file is not valid JSON"
        }, true)
    end

    njt.say(content)
end

local function getAppConfig(req, res, next)
    -- Set JSON header
    res:set_header("Content-Type", "application/json")

    -- Get app name from route parameter
    local app_name = req.params.name
    if not app_name then
        njt.log(njt.ERR, "No app name provided in request")
        return res:json({
            code = RETURN_CODE.CONFIG_SCHEMA_ERR,
            msg = "App name is required"
        }, true)
    end

    -- Validate app name (no spaces, consistent with deploy_app_package)
    if string.match(app_name, "%s") then
        njt.log(njt.ERR, "Invalid app name: ", app_name)
        return res:json({
            code = RETURN_CODE.CONFIG_SCHEMA_ERR,
            msg = "App name cannot contain spaces"
        }, true)
    end

    local config_content = deployAppSrv.read_config(app_name)
    if config_content then
        njt.say(cjson.encode(config_content))
    else
        njt.say("{}")
    end
end

local function postAppConfig(req, res, next)
    -- Get app name from route parameter
    local app_name = req.params.name
    if not app_name then
        return res:json({
            code = RETURN_CODE.CONFIG_SCHEMA_ERR,
            msg = "App name is required"
        }, true)
    end

    -- Validate app name (no spaces, consistent with deploy_app_package)
    if string.match(app_name, "%s") then
        return res:json({
            code = RETURN_CODE.CONFIG_SCHEMA_ERR,
            msg = "App name cannot contain spaces"
        }, true)
    end

    -- Construct file path
    local config_path = string.format("%s/%s/config.json", constValue.APPS_FOLDER, app_name)

    -- Check if app directory exists
    local dir_check = io.open(string.format("%s/%s", constValue.APPS_FOLDER, app_name), "r")
    if not dir_check then
        return res:json({
            code = RETURN_CODE.CONFIG_SCHEMA_ERR,
            msg = "App not found: " .. app_name
        }, true)
    end
    dir_check:close()

    -- Get request body
    local body = util.getBodyData()
    if not body then
        return res:json({
            code = RETURN_CODE.CONFIG_SCHEMA_ERR,
            msg = "Request body is required"
        }, true)
    end

    -- deSerialize body to object
    local success, configObj = pcall(cjson.decode, body)
    if not success then
        return res:json({
            code = RETURN_CODE.CONFIG_SCHEMA_ERR,
            msg = "Invalid JSON data"
        }, true)
    end

    -- Write config
    local ok, err = deployAppSrv.write_config(app_name, configObj)
    if not ok then
        return res:json({
            code = RETURN_CODE.CONFIG_SCHEMA_ERR,
            msg = err
        }, err:match("not found") and 404 or 500)
    end
    return res:json({
        code = 0,
        msg = "success"
    }, true)
end

deployRouter:post("/app", deployApp)
deployRouter:delete("/app", delApp)
deployRouter:get("/app/:name/config/schema", getAppConfigSchema)
deployRouter:get("/app/:name/config", getAppConfig)
deployRouter:post("/app/:name/config", postAppConfig)

return deployRouter
