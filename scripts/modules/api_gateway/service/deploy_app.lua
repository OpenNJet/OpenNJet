local _M = {}

local cjson = require("cjson")
local apiGroupDao = require("api_gateway.dao.api_group")
local constValue = require("api_gateway.config.const")
local oas3util = require("api_gateway.utils.oas3_import")
local dbConfig = require("api_gateway.config.db")
local tokenLib = require("njt.token")
local njetApi = require("api_gateway.service.njet")
local util = require("api_gateway.utils.util")

local function get_dyn_upstream_name(app_name, loc_path)
    return app_name .. "_dyn_" .. string.gsub(loc_path, "/", "_")
end

local function encrypt_value(value)
    if type(value) ~= "string" then
        return value -- Only encrypt strings
    end

    local ok, ri = pcall(require, "ssh_remote_mod")
    if ok then
        local rc, msg = ri.encrypt_msg(value)
        if rc ~= 0 then
            return nil, "encryption failed, check ssh_remote_mod.so"
        end
        return {
            __encrypted = true,
            value = msg
        }
    else
        return nil, "ssh_remote_mod.so not found"
    end
end

-- Utility: Decrypt a value using AES-256-CBC with PKCS#7 padding
local function decrypt_value(encrypted_obj)
    if type(encrypted_obj) ~= "table" or not encrypted_obj.__encrypted then
        return encrypted_obj -- Not encrypted
    end
    local ok, ri = pcall(require, "ssh_remote_mod")
    if ok then
        local rc, msg = ri.decrypt_msg(encrypted_obj.value)
        if rc ~= 0 then
            return nil, "Decryption failed, config_file is not correct"
        end
        return msg
    else
        return nil, "ssh_remote_mod.so not found"
    end
end

local function getAllFieldsNeedEncryption(app_name)
    local fields = {}

    local config_path = string.format("%s/%s/META-INF/%s", constValue.APPS_FOLDER, app_name, constValue.APP_SCHEMA_FILE)
    -- Check if file exists
    local file = io.open(config_path, "r")
    if not file then
        return fields
    end
    -- Read file content
    local content = file:read("*a")
    file:close()
    -- Parse JSON
    local success, config = pcall(cjson.decode, content)
    if not success then
        return fields
    end

    for k, v in pairs(config) do
        if type(v) == "table" and v["x-component"] == "Input.Password" then
            fields[k] = true
        end
    end
    return fields
end

function _M.read_manifest(app_name)
    local manifest_path = string.format("%s/%s/META-INF/manifest.json", constValue.APPS_FOLDER, app_name)

    -- Check if file exists
    local file = io.open(manifest_path, "r")
    if not file then
        return false, "manifest file not found for app: " .. app_name
    end

    -- Read file content
    local content = file:read("*a")
    file:close()

    -- Parse JSON
    local success, config = pcall(cjson.decode, content)
    if not success then
        return false, "manifest file is not valid JSON"
    end

    return true, config
end

-- Read and decrypt config.json
function _M.read_config(app_name)
    local config_path = string.format("%s/%s/config.json", constValue.APPS_FOLDER, app_name)

    -- Check if file exists
    local file = io.open(config_path, "r")
    if not file then
        return nil, "Config file not found for app: " .. app_name
    end

    -- Read file content
    local content = file:read("*a")
    file:close()

    -- Parse JSON
    local success, config = pcall(cjson.decode, content)
    if not success then
        return nil, "Config file is not valid JSON"
    end

    local fs = getAllFieldsNeedEncryption(app_name)
    -- Decrypt fields
    for key, value in pairs(config) do
        if fs[key] then
            local decrypted, err = decrypt_value(value)
            if not decrypted then
                return nil, "Failed to decrypt config: " .. err
            end
            config[key] = decrypted
        end
    end

    return config
end

-- Execute a command and capture stdout/stderr
local function execute_command(cmd)
    local tmpfile = "/tmp/cmd_output_" .. math.random(1000, 9999) .. ".tmp"
    local full_cmd = string.format("%s >%q 2>&1", cmd, tmpfile)
    local status = os.execute(full_cmd)
    local file = io.open(tmpfile, "r")
    local output = file and file:read("*a") or "No output captured"
    if file then
        file:close()
    end
    os.execute(string.format("rm -f %q", tmpfile))
    return status, output
end

-- Encrypt and write config.json
function _M.write_config(app_name, config)
    local config_path = string.format("%s/%s/config.json", constValue.APPS_FOLDER, app_name)

    -- Check if app directory exists
    local dir_check = io.open(string.format("%s/%s", constValue.APPS_FOLDER, app_name), "r")
    if not dir_check then
        return nil, "App not found: " .. app_name
    end
    dir_check:close()

    local fs = getAllFieldsNeedEncryption(app_name)
    -- Encrypt sensitive fields
    local config_copy = {}
    for key, value in pairs(config) do
        if fs[key] then
            local encrypted, err = encrypt_value(value)
            if not encrypted then
                return nil, "Failed to encrypt config: " .. err
            end
            config_copy[key] = encrypted
        else
            config_copy[key] = value
        end
    end

    -- Serialize to JSON
    local json_content = cjson.encode(config_copy)
    -- Write to config.json
    local file, err = io.open(config_path, "w")
    if not file then
        return nil, "Failed to write config file: " .. err
    end

    file:write(json_content)
    file:close()

    -- Set permissions
    local chmod_cmd = string.format("chmod 644 %q", config_path)
    local chmod_status, chmod_output = execute_command(chmod_cmd)
    if chmod_status ~= 0 then
        njt.log(njt.ERR, "Failed to set config file permissions: ", chmod_output)
        -- Continue, as write succeeded
    end

    tokenLib.token_set(constValue.APP_CONFIG_CHANGES_KEY_PREFIX .. app_name, njt.now(),
        config.changes_notification_lifetime)

    return true
end

-- Extract ZIP file to a target directory
local function extract_map_package(zip_path, temp_dir)
    if not zip_path or not temp_dir then
        return nil, "zip_path and temp_dir are required"
    end

    -- Check if ZIP file exists
    local file = io.open(zip_path, "r")
    if not file then
        return nil, "ZIP file not found: " .. zip_path
    end
    file:close()

    -- Create temporary directory
    local mkdir_cmd = string.format("mkdir -p %q", temp_dir)
    local mkdir_ok, mkdir_err = os.execute(mkdir_cmd)
    if mkdir_ok ~= 0 then
        return nil, "Failed to create temp directory: " .. (mkdir_err or "unknown error")
    end

    -- Set temp directory permissions to 755
    local chmod_dir_cmd = string.format("chmod 755 %q", temp_dir)
    local chmod_dir_ok, chmod_dir_err = os.execute(chmod_dir_cmd)
    if chmod_dir_ok ~= 0 then
        return nil, "Failed to set temp directory permissions: " .. (chmod_dir_err or "unknown error")
    end

    -- Extract ZIP
    local unzip_cmd = string.format("unzip -o -q %q -d %q", zip_path, temp_dir)
    local unzip_ok, unzip_err = os.execute(unzip_cmd)
    if unzip_ok ~= 0 then
        return nil, "Failed to extract ZIP: " .. (unzip_err or "unknown error")
    end

    -- Set permissions for extracted files (directories: 755, files: 644)
    local chmod_files_cmd = string.format(
        "find %q -type d -exec chmod 755 {} \\; && find %q -type f -exec chmod 644 {} \\;", temp_dir, temp_dir)
    local chmod_files_ok, chmod_files_err = os.execute(chmod_files_cmd)
    if chmod_files_ok ~= 0 then
        return nil, "Failed to set extracted file permissions: " .. (chmod_files_err or "unknown error")
    end

    return true
end

-- Read manifest.json from extracted directory
local function read_manifest(temp_dir)
    local manifest_path = temp_dir .. "/META-INF/manifest.json"
    local file = io.open(manifest_path, "r")
    if not file then
        return nil, "Manifest not found at " .. manifest_path
    end
    local content = file:read("*a")
    file:close()
    local success, manifest = pcall(cjson.decode, content)
    if not success then
        return nil, "Failed to parse manifest: " .. manifest
    end
    return manifest
end

-- Validate appname (no spaces)
local function validate_appname(appname)
    if not appname or appname == "" then
        return false, "appname is empty"
    end
    if string.match(appname, "%s") then
        return false, "appname contains spaces: " .. appname
    end
    return true
end

local function file_exists(file)
    local f = io.open(file, "r")
    if f then
        f:close()
        return true
    end
    return false
end

-- Move extracted contents to final directory
local function move_extracted_contents(temp_dir, target_dir)
    -- try to keep old config.json , ignore error
    if file_exists(string.format("%s/config.json", target_dir)) then
        local mv_cmd = string.format("mv %s/config.json %s", target_dir, temp_dir)
        execute_command(mv_cmd)
    end

    -- Remove existing target_dir to allow overwrite
    local rm_cmd = string.format("rm -rf %q", target_dir)
    local rm_status, rm_output = execute_command(rm_cmd)
    if rm_status ~= 0 then
        return nil, "Failed to clear target directory: " .. rm_output
    end

    -- Create target directory with 755 permissions
    local mkdir_cmd = string.format("mkdir -p %q && chmod 755 %q", target_dir, target_dir)
    local mkdir_status, mkdir_output = execute_command(mkdir_cmd)
    if mkdir_status ~= 0 then
        return nil, "Failed to create target directory: " .. mkdir_output
    end

    -- Move contents
    local mv_cmd = string.format("mv %q/* %q", temp_dir, target_dir)
    local mv_status, mv_output = execute_command(mv_cmd)
    if mv_status ~= 0 then
        return nil, "Failed to move contents: " .. mv_output
    end

    -- Set permissions for moved files (directories: 755, files: 644)
    local chmod_files_cmd = string.format(
        "find %q -type d -exec chmod 755 {} \\; && find %q -type f -exec chmod 644 {} \\;", target_dir, target_dir)
    local chmod_files_status, chmod_files_output = execute_command(chmod_files_cmd)
    if chmod_files_status ~= 0 then
        return nil, "Failed to set target file permissions: " .. chmod_files_output
    end

    return true
end

local function validate_manifest(manifest, temp_dir)
    local appname = manifest.app and manifest.app.name
    if not appname then
        return false, "No app.name found in manifest"
    end

    local valid, appname_err = validate_appname(appname)
    if not valid then
        return false, "Invalid appname: " .. appname_err
    end

    -- Check icon_file
    local icon_file = manifest.app.icon_file
    if not icon_file then
        return false, "No icon_file specified in manifest"
    end
    local icon_path = temp_dir .. "/META-INF/" .. icon_file
    local file = io.open(icon_path, "r")
    if not file then
        return false, "icon_file not found: " .. icon_path
    end
    file:close()
    -- Validate icon_file format (png, jpg, jpeg)
    local icon_ext = icon_file:lower():match("%.(%w+)$")
    if not icon_ext or not ({
        png = true,
        jpg = true,
        jpeg = true
    })[icon_ext] then
        return false, "icon_file must be .png, .jpg, or .jpeg: " .. icon_file
    end
    local file = io.open(icon_path, "rb") -- Binary mode
    if file then
        local header = file:read(8) -- Read first 8 bytes
        file:close()
        if not header then
            return false, "Failed to read icon_file: " .. icon_path
        end
        -- PNG: Starts with 89 50 4E 47 0D 0A 1A 0A
        -- JPEG: Starts with FF D8
        local is_png = header:match("^\137PNG\r\n\026\n")
        local is_jpeg = header:match("^\255\216")
        if not (is_png or is_jpeg) then
            return false, "icon_file is not a valid PNG or JPEG: " .. icon_file
        end
    else
        return false, "icon_file not found: " .. icon_path
    end

    -- Check api_file
    local api_file = manifest.app.api_file
    if not api_file then
        return false, "No api_file specified in manifest"
    end
    local api_path = temp_dir .. "/META-INF/" .. api_file
    file = io.open(api_path, "r")
    if not file then
        return false, "api_file not found: " .. api_path
    end
    local api_content = file:read("*a")
    file:close()

    -- Validate api_file is valid JSON
    local success, api_data = pcall(cjson.decode, api_content)
    if not success then
        return false, "api_file is not valid JSON: " .. api_file .. ": " .. api_data
    end

    -- Validate api_file is an OpenAPI definition
    if not api_data.openapi and not api_data.swagger then
        return false, "api_file is not a valid OpenAPI definition (missing openapi or swagger field): " .. api_file
    end

    if not manifest.deployment or not manifest.deployment.type or not manifest.deployment.entry_point then
        return false, "deployment.type and deployment.entry_point are mandatory fields"
    end

    return true, api_content
end

local function replace_app_prefix(value, app_name)
    return string.gsub(value, "${APP_PREFIX}", constValue.APPS_FOLDER .. "/" .. app_name)
end

local function getLocationBody(app_name, loc_path, prop)
    local body = {}
    for k, v in pairs(prop) do
        if k == "proxy_pass" then
            local schema = v.schema or "http"
            local upstream_name = get_dyn_upstream_name(app_name, loc_path)
            local url = v.url or ""
            local pv = schema .. "://" .. upstream_name .. url
            table.insert(body, k .. " " .. pv .. ";")
        elseif k == "__access_control" then
            -- add api gateway access check block
            table.insert(body, "access_by_lua_block {")
            table.insert(body, "local ac=require(\"api_gateway.access.control\")")
            local path_prefix = loc_path:match("^/[^/]+") or loc_path
            table.insert(body, "local access=ac.new(\"" .. path_prefix .. "\")")
            table.insert(body, "access:check()")
            table.insert(body, "}")
        else
            if type(v) == "string" then
                table.insert(body, k .. " " .. replace_app_prefix(v, app_name) .. ";")
            elseif util.isArray(v) then
                for _, vv in ipairs(v) do
                    table.insert(body, k .. " " .. replace_app_prefix(vv, app_name) .. ";")
                end
            end
        end
    end

    njt.log(njt.DEBUG, "adding body :" .. table.concat(body, "\n"))
    return table.concat(body, "\n")
end

-- remove vs location upstream
local function remove_app_from_njet(manifest)
    local server_name = manifest.deployment.server_name or ""
    if manifest and manifest.deployment and manifest.deployment.locations then
        for _, loc in ipairs(manifest.deployment.locations) do
            njetApi.delLocationForApp(server_name, loc.path)
            if loc.properties and loc.properties.proxy_pass then
                njetApi.delCUpstream(get_dyn_upstream_name(manifest.app.name, loc.path))
            end
        end
    end
    if manifest and manifest.deployment and manifest.deployment.type == "vs" then
        njetApi.delVsForApp(server_name)
    end
end

function _M.remove_app(app_name)
    local target_dir = string.format("%s/%s", constValue.APPS_FOLDER, app_name)
    local manifest, manifest_err = read_manifest(target_dir)
    if  manifest then
        --using manifest to remove app, such as vs/upstream/location 
        remove_app_from_njet(manifest)
        os.execute("rm -rf  " .. target_dir)
    end

    local ok, apiGroupObj = apiGroupDao.getApiGroupByName(app_name)
    if not ok then
        return false, "Unable to find api_group by name: " .. app_name
    end

    apiGroupDao.deleteApiGroupById(apiGroupObj.id)
    return true, ""
end

local function check_arch(expected_arch)
    -- Get system architecture
    local handle = io.popen("uname -m")
    local arch = handle:read("*a"):gsub("\n", "")
    handle:close()

    -- Normalize architecture strings by removing "-" and "_"
    local normalized_expected_arch = expected_arch:gsub("[-_]", "")
    local normalized_arch = arch:gsub("[-_]", "")

    -- Check for match: either normalized strings are equal, or arm64/aarch64 special case
    return normalized_arch == normalized_expected_arch or
               (normalized_arch == "aarch64" and normalized_expected_arch == "arm64")
end

-- Main deployment function
function _M.deploy_app_package(zip_path)
    -- Create a unique temporary directory for extraction
    local temp_dir = "/tmp/map_extract_" .. njt.now() .. "_" .. math.random(1000, 9999)
    njt.log(njt.DEBUG, "Extracting ", zip_path, " to temp dir: ", temp_dir)

    -- Create icons directory for the app
    local icon_dir = constValue.APPS_FOLDER .. "/__icons"
    local mkdir_icon_cmd = string.format("mkdir -p %q && chmod 755 %q", icon_dir, icon_dir)
    local mkdir_icon_status, mkdir_icon_output = execute_command(mkdir_icon_cmd)
    if mkdir_icon_status ~= 0 then
        return false, "无法创建__icons目录"
    end
    -- Step 1: Extract ZIP to temp directory
    local ok, err = extract_map_package(zip_path, temp_dir)
    if not ok then
        return false, "Extraction failed: " .. err
    end

    -- Step 2: Read manifest to get appname
    local manifest, manifest_err = read_manifest(temp_dir)
    if not manifest then
        os.execute(string.format("rm -rf %q", temp_dir)) -- Clean up
        return false, "Failed to read manifest: " .. manifest_err
    end

    if manifest.app.arch and manifest.app.arch ~= "" then
        local ok = check_arch(manifest.app.arch)
        if not ok then
            return false, "Package is for arch: " .. manifest.app.arch .. ", not compatible with current hardware"
        end
    end

    local ok, api_content = validate_manifest(manifest, temp_dir)
    if not ok then
        os.execute(string.format("rm -rf %q", temp_dir)) -- Clean up
        return false, api_content
    end

    -- Step 3: Move contents to final directory
    local target_dir = string.format("%s/%s", constValue.APPS_FOLDER, manifest.app.name)
    local manifest_file = string.format("%s/META-INF/manifest.json", target_dir)
    if file_exists(manifest_file) then
        return false, "应用已存在，请核对应用名称"
    end
    local move_ok, move_err = move_extracted_contents(temp_dir, target_dir)
    if not move_ok then
        os.execute(string.format("rm -rf %q", temp_dir)) -- Clean up
        _M.remove_app(manifest.app.name)
        return false, "从临时目录拷贝应用出错: " .. move_err
    end

    -- create api_group
    local inputObj = {}
    inputObj.name = manifest.app.name
    local first_part = string.match(manifest.deployment.entry_point, "^/[^/]+")
    inputObj.base_path = first_part
    inputObj.desc = manifest.app.description or ""
    inputObj.domain = ""
    inputObj.user_id = njt.req.get_headers()[constValue.HEADER_USER_ID] or ""

    local ok, apiGroupObj = apiGroupDao.getApiGroupByName(inputObj.name)
    if not ok then
        ok, apiGroupObj = apiGroupDao.createApiGroup(inputObj)
        if not ok then
            _M.remove_app(manifest.app.name)
            return false, "无法创建 api_group "
        end
    else
        inputObj.id = apiGroupObj.id
        apiGroupDao.updateApiGroup(inputObj)
    end
    -- import openapi.json
    local ok, msg = oas3util.oas3_json_import(api_content, dbConfig.db_file, apiGroupObj.id)
    if not ok then
        _M.remove_app(manifest.app.name)
        return false, "无法从应用的json文件导入API"
    else
        njt.log(njt.DEBUG, "oas3 json import result: " .. tostring(msg))
    end

    -- copy icon file 
    local icon_file = manifest.app.icon_file
    local icon_ext = icon_file:lower():match("%.(%w+)$")
    local icon_path = target_dir .. "/META-INF/" .. icon_file
    os.execute(string.format("cp %q %q", icon_path,
        constValue.APPS_FOLDER .. "/__icons/" .. manifest.app.name .. "." .. icon_ext))

    -- add vs, upstream and location
    remove_app_from_njet(manifest)
    local server_name = manifest.deployment.server_name or ""
    if manifest.deployment.type == "vs" and server_name ~= "" then
        local ok, msg = njetApi.addVsForApp(server_name)
        if not ok then
            -- if not able to add vs, print err and continue to add location
            njt.log(njt.ERR, "not able to add vs: " .. msg)
        end
    end

    if manifest.deployment.locations then
        for _, loc in ipairs(manifest.deployment.locations) do
            if loc.properties and loc.properties.proxy_pass and loc.properties.proxy_pass.servers then
                njetApi.addCUpstream(get_dyn_upstream_name(manifest.app.name, loc.path),
                    loc.properties.proxy_pass.servers)
            end
            local ok, msg = njetApi.addLocationForApp(server_name, loc.path,
                getLocationBody(manifest.app.name, loc.path, loc.properties))
            if not ok then
                _M.remove_app(manifest.app.name)
                return false, msg
            end
        end
    end

    return true, ""
end

return _M
