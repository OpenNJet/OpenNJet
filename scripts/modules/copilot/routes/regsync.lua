local lor = require("lor.index")
local cjson = require("cjson")
local mqconf = require("njt.mqconf")
local fileUtil = require("common_util.file")
local commonUtil = require("common_util")
local copilotUtil = require("copilot.util")

local regsyncRouter = lor:Router()

local RETURN_CODE = {
    SUCCESS = 0,
    GET_CONFS_ERROR = 10,
    CONF_FILENAME_EMPTY = 20,
    CONF_FILE_READ_ERROR = 30,
    LUA_LIB_NOT_AVAILABLE = 40,
    NOT_VALID_TOML_FORMAT = 50,
    NOT_VALID_JSON_FORMAT = 60,
    CONF_FILE_WRITE_ERROR = 70,
    COPILOT_RESTART_ERROR = 80,
    NOT_VALID_REQUEST_DATA = 90
}

local REGSYNC_MODULE_NAME = "njt_helper_go_copilot_module.so"

local function readTomlFileAndConvertToObj(filename)
    local retObj = {}

    if not filename or filename == "" then
        retObj.code = RETURN_CODE.CONF_FILENAME_EMPTY
        retObj.msg = "copilot's conf file name is empty, check njet conf"
        return retObj
    end

    local content = fileUtil.read_from_file(filename)
    if not content then
        retObj.code = RETURN_CODE.CONF_FILE_READ_ERROR
        retObj.msg = "can't read file: " .. filename
        return retObj
    end

    local convert_func = nil
    local ok, ri = pcall(require, "ssh_remote_mod")
    if ok then
        convert_func = ri["toml_to_json"]
    end
    if not convert_func then
        retObj.code = RETURN_CODE.LUA_LIB_NOT_AVAILABLE
        retObj.msg = "toml related lua lib is not in search path "
        return retObj
    end

    local rc, cv = convert_func(content)

    if rc == 0 then
        local ok, cv2 = pcall(cjson.decode, cv)
        if ok then
            retObj.code = RETURN_CODE.SUCCESS
            retObj.msg = "success"
            retObj.data = cv2
        else
            retObj.code = RETURN_CODE.NOT_VALID_JSON_FORMAT
            retObj.msg = "config file: " .. filename .. " convert to wrong json format"
        end
    else
        retObj.code = RETURN_CODE.NOT_VALID_TOML_FORMAT
        retObj.msg = "config file: " .. filename .. " is not in valid toml format"
    end

    return retObj
end

local function getRegsyncLabels(req, res, next)
    local retObj = {}
    local ok, confs = mqconf.getCopilotConfsByModuleName(REGSYNC_MODULE_NAME)
    if ok then
        retObj.code = RETURN_CODE.SUCCESS
        retObj.msg = "success"
        retObj.data = {}
        for _, c in ipairs(confs) do
            local obj = readTomlFileAndConvertToObj(c.conf_file)
            if obj.data and obj.data.copilot and obj.data.copilot.copilotType == "regsync" then
                table.insert(retObj.data, c.label)
            end
        end
    else
        retObj.code = RETURN_CODE.GET_CONFS_ERROR
        retObj.msg = confs
    end
    res:json(retObj, false)
end

-- 通过 regsync copilot label 获取当前的配置内容
local function getFullConfByLabel(label)
    local retObj = {}
    local ok, confs = mqconf.getCopilotConfsByLabelName(label)
    if ok then
        retObj = readTomlFileAndConvertToObj(confs[1].conf_file)
    else
        retObj.code = RETURN_CODE.GET_CONFS_ERROR
        retObj.msg = "can't find copilot by label name: " .. label
    end
    ::GETCONFLABEL::

    return retObj
end

-- 通过 regsync copilot label 写入配置内容
local function writeFullConfByLabel(label, content)
    local retObj = {}
    local ok, confs = mqconf.getCopilotConfsByLabelName(label)
    if ok then
        local filename = confs[1].conf_file

        local convert_func = nil
        local ok, ri = pcall(require, "ssh_remote_mod")
        if ok then
            convert_func = ri["json_to_toml"]
        end
        if not convert_func then
            retObj.code = RETURN_CODE.LUA_LIB_NOT_AVAILABLE
            retObj.msg = "toml related lua lib is not in search path "
            return retObj
        end
        local rc, cv = convert_func(cjson.encode(content))

        if rc ~= 0 then
            retObj.code = RETURN_CODE.NOT_VALID_JSON_FORMAT
            retObj.msg = cv
            return retObj
        end

        local ok, msg = fileUtil.write_to_file(filename, cv)
        if ok then
            ok, msg = copilotUtil.restartCopilotByLabel(label)
            if ok then
                retObj.code = RETURN_CODE.SUCCESS
                retObj.msg = "success"
            else
                retObj.code = RETURN_CODE.COPILOT_RESTART_ERROR
                retObj.msg = msg
            end
        else
            retObj.code = RETURN_CODE.CONF_FILE_WRITE_ERROR
            retObj.msg = msg
        end
    else
        retObj.code = RETURN_CODE.GET_CONFS_ERROR
        retObj.msg = "can't find copilot by label name: " .. label
    end
    return retObj
end

-- 对非绝对路径添加 $prefix 前缀， 目前路径中不做 ../ 的判断
local function addPrefixIfNecessary(filename)
    if not commonUtil.startsWith(filename, "/") then
        return njt.config.prefix() .. filename
    end
    return filename
end

local function convertFilePath(obj)
    if obj.etcd and obj.etcd.certFile then
        obj.etcd.certFile = addPrefixIfNecessary(obj.etcd.certFile)
    end
    if obj.etcd and obj.etcd.keyFile then
        obj.etcd.keyFile = addPrefixIfNecessary(obj.etcd.keyFile)
    end
    if obj.etcd and obj.etcd.trustedCAFile then
        obj.etcd.trustedCAFile = addPrefixIfNecessary(obj.etcd.trustedCAFile)
    end
    if obj.log and obj.log.file then
        obj.log.file = addPrefixIfNecessary(obj.log.file)
    end
end

-- 检查 PUT 请求的输入字段合法性
local function checkReplacedConfCorrectness(req_obj)
    local obj

    if req_obj.copilot then
        obj = req_obj.copilot
        if not obj.progName or not obj.copilotType then
             return false, "progName and copilotType fields are mandatory in copilot"
        end
    end

    if req_obj.etcd then
        obj = req_obj.etcd
        if not obj.framework then
            return false, "framework field is mandatory in etcd"
        end
        if not obj.endPoints or not commonUtil.isArray(obj.endPoints) then
            return false, "endPoints should be an array in etcd"
        end
    end

    if req_obj.log then
        obj = req_obj.log
        if not obj.level or not obj.file then
            return false, "level and file fields are mandatory in log"
        end
        local log_levels = {"error", "warning", "info", "debug"}
        local found = false
        for _, v in ipairs(log_levels) do
            if v == obj.level then
                found = true
                break
            end
        end
        if not found then
            return false, "valid level values are: error, warning, info, debug"
        end
    end

    if req_obj.njet then
        obj = req_obj.njet
        if not obj.apiUrl or not obj.loginId or not obj.loginPassword then
            return false, "apiUrl, loginId and loginPassword fields are mandatory in  njet"
        end

        if not obj.passwordEncrypted or obj.passwordEncrypted == false then
            -- try to encrypt password
            local convert_func = nil
            local ok, ri = pcall(require, "ssh_remote_mod")
            if ok then
                convert_func = ri["encrypt_msg"]
            end
            if convert_func then
                local rc, msg = convert_func(obj.loginPassword)
                if rc == 0 then
                    obj.passwordEncrypted = true
                    obj.loginPassword = msg
                end
            end
        end

        if obj.passwordEncrypted then
            -- try to decrypt password
            local convert_func = nil
            local ok, ri = pcall(require, "ssh_remote_mod")
            if ok then
                convert_func = ri["decrypt_msg"]
            end
            if convert_func then
                local rc, msg = convert_func(obj.loginPassword)
                if rc ~= 0 then
                    return false, "loginPassword is not correctly encrypted"
                end
            end
        end

    end

    if req_obj.watcher then
        obj = req_obj.watcher
        if not commonUtil.isArray(obj) then
            return false, "watcher should be an array obj"
        end
        for _, v in ipairs(obj) do
            if not v.properties or not v.properties.serviceName or not v.properties.upstreamName then
                return false,
                    "each watcher item should have properties field and have serviceName and upstreamName in it"
            end
        end
    end

    return true, ""
end

local function getConfByLabel(req, res, next)
    local retObj = getFullConfByLabel(req.params.label)
    res:json(retObj, false)
end

local function updateConfByLabel(req, res, next)
    local retObj = {}
    local label = req.params.label
    local req_body = commonUtil.getBodyData()
    local msg = ""
    local ok, req_obj = pcall(cjson.decode, req_body)
    if not ok then
        retObj.code = RETURN_CODE.NOT_VALID_JSON_FORMAT
        retObj.msg = "request data is not valid json"
        goto UPDATECONFLABEL
    end
    -- check submit data
    ok, msg = checkReplacedConfCorrectness(req_obj)
    if not ok then
        retObj.code = RETURN_CODE.NOT_VALID_REQUEST_DATA
        retObj.msg = msg
        goto UPDATECONFLABEL
    end

    -- convert relative file_name to fullpath file_name 
    convertFilePath(req_obj)

    retObj = writeFullConfByLabel(label, req_obj)

    ::UPDATECONFLABEL::
    res:json(retObj, false)
end

local function getEtcdConfByLabel(req, res, next)
    local retObj = getFullConfByLabel(req.params.label)
    local data = {}
    data = retObj.data.etcd
    retObj.data = data
    res:json(retObj, false)
end

local function updateEtcdConfByLabel(req, res, next)
    local retObj = {}
    local req_obj = {}
    local label = req.params.label
    local req_body = commonUtil.getBodyData()
    local msg = ""
    local ok, etcd_req_obj = pcall(cjson.decode, req_body)
    if not ok then
        retObj.code = RETURN_CODE.NOT_VALID_JSON_FORMAT
        retObj.msg = "request data is not valid json"
        goto UPDATE_ETCD_CONFLABEL
    end

    req_obj = {
        etcd = etcd_req_obj
    }

    ok, msg = checkReplacedConfCorrectness(req_obj)
    if not ok then
        retObj.code = RETURN_CODE.NOT_VALID_REQUEST_DATA
        retObj.msg = msg
        goto UPDATE_ETCD_CONFLABEL
    end

    retObj = getFullConfByLabel(label)

    if retObj.code == RETURN_CODE.SUCCESS then
        req_obj = retObj.data
        -- etcd 配置使用提交的数据
        req_obj.etcd = etcd_req_obj
        convertFilePath(req_obj)
        retObj = writeFullConfByLabel(label, req_obj)
    end

    ::UPDATE_ETCD_CONFLABEL::
    res:json(retObj, false)
end

local function getLogConfByLabel(req, res, next)
    local retObj = getFullConfByLabel(req.params.label)
    local data = {}
    data = retObj.data.log
    retObj.data = data
    res:json(retObj, false)
end

local function updateLogConfByLabel(req, res, next)
    local retObj = {}
    local req_obj = {}
    local label = req.params.label
    local req_body = commonUtil.getBodyData()
    local msg = ""
    local ok, log_req_obj = pcall(cjson.decode, req_body)
    if not ok then
        retObj.code = RETURN_CODE.NOT_VALID_JSON_FORMAT
        retObj.msg = "request data is not valid json"
        goto UPDATE_LOG_CONFLABEL
    end

    req_obj = {
        log = log_req_obj
    }

    ok, msg = checkReplacedConfCorrectness(req_obj)
    if not ok then
        retObj.code = RETURN_CODE.NOT_VALID_REQUEST_DATA
        retObj.msg = msg
        goto UPDATE_LOG_CONFLABEL
    end

    retObj = getFullConfByLabel(label)

    if retObj.code == RETURN_CODE.SUCCESS then
        req_obj = retObj.data
        -- log 配置使用提交的数据
        req_obj.log = log_req_obj
        convertFilePath(req_obj)
        retObj = writeFullConfByLabel(label, req_obj)
    end

    ::UPDATE_LOG_CONFLABEL::
    res:json(retObj, false)
end

local function getNjetConfByLabel(req, res, next)
    local retObj = getFullConfByLabel(req.params.label)
    local data = {}
    data = retObj.data.njet
    retObj.data = data
    res:json(retObj, false)
end

local function updateNjetConfByLabel(req, res, next)
    local retObj = {}
    local req_obj = {}
    local label = req.params.label
    local req_body = commonUtil.getBodyData()
    local msg = ""
    local ok, njet_req_obj = pcall(cjson.decode, req_body)
    if not ok then
        retObj.code = RETURN_CODE.NOT_VALID_JSON_FORMAT
        retObj.msg = "request data is not valid json"
        goto UPDATE_NJET_CONFLABEL
    end

    req_obj = {
        njet = njet_req_obj
    }

    ok, msg = checkReplacedConfCorrectness(req_obj)
    if not ok then
        retObj.code = RETURN_CODE.NOT_VALID_REQUEST_DATA
        retObj.msg = msg
        goto UPDATE_NJET_CONFLABEL
    end

    retObj = getFullConfByLabel(label)

    if retObj.code == RETURN_CODE.SUCCESS then
        req_obj = retObj.data
        -- njet 配置使用提交的数据
        req_obj.njet = njet_req_obj
        convertFilePath(req_obj)
        retObj = writeFullConfByLabel(label, req_obj)
    end

    ::UPDATE_NJET_CONFLABEL::
    res:json(retObj, false)
end

local function getWatchersConfByLabel(req, res, next)
    local retObj = getFullConfByLabel(req.params.label)
    local data = {}
    data = retObj.data.watcher
    retObj.data = data
    res:json(retObj, false)
end

local function updateWatchersConfByLabel(req, res, next)
    local retObj = {}
    local req_obj = {}
    local label = req.params.label
    local req_body = commonUtil.getBodyData()
    local msg = ""
    local ok, watchers_req_obj = pcall(cjson.decode, req_body)
    if not ok then
        retObj.code = RETURN_CODE.NOT_VALID_JSON_FORMAT
        retObj.msg = "request data is not valid json"
        goto UPDATE_WATCHERS_CONFLABEL
    end

    req_obj = {
        watcher = watchers_req_obj
    }

    ok, msg = checkReplacedConfCorrectness(req_obj)
    if not ok then
        retObj.code = RETURN_CODE.NOT_VALID_REQUEST_DATA
        retObj.msg = msg
        goto UPDATE_WATCHERS_CONFLABEL
    end

    retObj = getFullConfByLabel(label)

    if retObj.code == RETURN_CODE.SUCCESS then
        req_obj = retObj.data
        -- njet 配置使用提交的数据
        req_obj.watcher = watchers_req_obj
        convertFilePath(req_obj)
        retObj = writeFullConfByLabel(label, req_obj)
    end

    ::UPDATE_WATCHERS_CONFLABEL::
    res:json(retObj, false)
end

local function checkWatcherConfCorrectness(obj)
    if not obj.properties or not obj.properties.serviceName or not obj.properties.upstreamName then
        return false, "watcher item should have properties field and have serviceName and upstreamName in it"
    end
    return true, ""
end

local function addWatcherConfByLabel(req, res, next)
    local retObj = {}
    local req_obj = {}
    local label = req.params.label
    local req_body = commonUtil.getBodyData()
    local msg = ""
    local ok, watcher_req_obj = pcall(cjson.decode, req_body)
    if not ok then
        retObj.code = RETURN_CODE.NOT_VALID_JSON_FORMAT
        retObj.msg = "request data is not valid json"
        goto ADD_WATCHER_CONFLABEL
    end

    ok, msg = checkWatcherConfCorrectness(watcher_req_obj)

    if not ok then
        retObj.code = RETURN_CODE.NOT_VALID_REQUEST_DATA
        retObj.msg = msg
        goto ADD_WATCHER_CONFLABEL
    end

    retObj = getFullConfByLabel(label)
    if retObj.code == RETURN_CODE.SUCCESS then
        local watchers = retObj.data.watcher
        if not watchers then
            watchers = {}
        end
        -- 添加 watcher 时，serviceName 不能和已有的配置重复
        for _, w in ipairs(watchers) do
            if w.properties.serviceName == watcher_req_obj.properties.serviceName then
                retObj.code = RETURN_CODE.NOT_VALID_REQUEST_DATA
                retObj.msg = "duplicated watcher conf, serviceName should be unique"
                retObj.data = nil
                goto ADD_WATCHER_CONFLABEL
            end
        end

        table.insert(watchers, watcher_req_obj)
        req_obj = retObj.data
        req_obj.watcher = watchers
        convertFilePath(req_obj)
        retObj = writeFullConfByLabel(label, req_obj)
    end

    ::ADD_WATCHER_CONFLABEL::
    res:json(retObj, false)
end

local function getWatcherConfByLabelAndID(req, res, next)
    local retObj = {}

    local label = req.params.label
    local watcherIndex = tonumber(req.params.id)
    if not watcherIndex then
        retObj.code = RETURN_CODE.NOT_VALID_REQUEST_DATA
        retObj.msg = "id in path parameter should be a number"
        goto GET_WATCHER_CONF_LABELANDID
    end

    retObj = getFullConfByLabel(label)
    if not retObj.data.watcher or watcherIndex + 1 > #retObj.data.watcher then
        retObj.code = RETURN_CODE.NOT_VALID_REQUEST_DATA
        retObj.msg = "id in more than watcher size"
        retObj.data = nil
        goto GET_WATCHER_CONF_LABELANDID
    end

    retObj.code = RETURN_CODE.SUCCESS
    retObj.msg = "success"
    retObj.data = retObj.data.watcher[watcherIndex + 1]

    ::GET_WATCHER_CONF_LABELANDID::
    res:json(retObj, false)
end

local function updateWatcherConfByLabelAndID(req, res, next)
    local retObj = {}
    local req_body = commonUtil.getBodyData()
    local msg = ""
    local ok
    local watcher_req_obj
    local label = req.params.label
    local watcherIndex = tonumber(req.params.id)
    if not watcherIndex then
        retObj.code = RETURN_CODE.NOT_VALID_REQUEST_DATA
        retObj.msg = "id in path parameter should be a number"
        goto UPDATE_WATCHER_CONF_LABELANDID
    end

    ok, watcher_req_obj = pcall(cjson.decode, req_body)
    if not ok then
        retObj.code = RETURN_CODE.NOT_VALID_JSON_FORMAT
        retObj.msg = "request data is not valid json"
        goto UPDATE_WATCHER_CONF_LABELANDID
    end

    ok, msg = checkWatcherConfCorrectness(watcher_req_obj)
    if not ok then
        retObj.code = RETURN_CODE.NOT_VALID_REQUEST_DATA
        retObj.msg = msg
        goto UPDATE_WATCHER_CONF_LABELANDID
    end

    retObj = getFullConfByLabel(label)
    if not retObj.data.watcher or watcherIndex + 1 > #retObj.data.watcher then
        retObj.code = RETURN_CODE.NOT_VALID_REQUEST_DATA
        retObj.msg = "id in more than watcher size"
        retObj.data = nil
        goto UPDATE_WATCHER_CONF_LABELANDID
    else
        local watchers = retObj.data.watcher
        -- 更新 watcher 时，serviceName 不能和已有的配置重复
        for index, w in ipairs(watchers) do
            if index ~= watcherIndex + 1 and w.properties.serviceName == watcher_req_obj.properties.serviceName then
                retObj.code = RETURN_CODE.NOT_VALID_REQUEST_DATA
                retObj.msg = "duplicated watcher conf, serviceName should be unique"
                retObj.data = nil
                goto UPDATE_WATCHER_CONF_LABELANDID
            end
        end

        retObj.data.watcher[watcherIndex + 1] = watcher_req_obj
        convertFilePath(retObj.data)
        retObj = writeFullConfByLabel(label, retObj.data)
    end

    ::UPDATE_WATCHER_CONF_LABELANDID::
    res:json(retObj, false)
end

local function deleteWatcherConfByLabelAndID(req, res, next)
    local retObj = {}
    local req_body = commonUtil.getBodyData()

    local label = req.params.label
    local watcherIndex = tonumber(req.params.id)
    if not watcherIndex then
        retObj.code = RETURN_CODE.NOT_VALID_REQUEST_DATA
        retObj.msg = "id in path parameter should be a number"
        goto DELETE_WATCHER_CONF_LABELANDID
    end

    retObj = getFullConfByLabel(label)
    if not retObj.data.watcher or watcherIndex + 1 > #retObj.data.watcher then
        retObj.code = RETURN_CODE.NOT_VALID_REQUEST_DATA
        retObj.msg = "id in more than watcher size"
        retObj.data = nil
        goto DELETE_WATCHER_CONF_LABELANDID
    else
        table.remove(retObj.data.watcher, watcherIndex + 1)
        convertFilePath(retObj.data)
        retObj = writeFullConfByLabel(label, retObj.data)
    end

    ::DELETE_WATCHER_CONF_LABELANDID::
    res:json(retObj, false)
end

regsyncRouter:get("", getRegsyncLabels)
regsyncRouter:get("/:label", getConfByLabel)
regsyncRouter:put("/:label", updateConfByLabel)
regsyncRouter:get("/:label/etcd", getEtcdConfByLabel)
regsyncRouter:put("/:label/etcd", updateEtcdConfByLabel)
regsyncRouter:get("/:label/log", getLogConfByLabel)
regsyncRouter:put("/:label/log", updateLogConfByLabel)
regsyncRouter:get("/:label/njet", getNjetConfByLabel)
regsyncRouter:put("/:label/njet", updateNjetConfByLabel)
regsyncRouter:get("/:label/watchers", getWatchersConfByLabel)
regsyncRouter:put("/:label/watchers", updateWatchersConfByLabel)
regsyncRouter:put("/:label/watcher", addWatcherConfByLabel)
regsyncRouter:get("/:label/watcher/:id", getWatcherConfByLabelAndID)
regsyncRouter:post("/:label/watcher/:id", updateWatcherConfByLabelAndID)
regsyncRouter:delete("/:label/watcher/:id", deleteWatcherConfByLabelAndID)

return regsyncRouter
