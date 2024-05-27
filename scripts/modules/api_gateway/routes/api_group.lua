local lor = require("lor.index")
local cjson = require("cjson")
local util = require("api_gateway.utils.util")
local oas3util = require("api_gateway.utils.oas3_import")
local config = require("api_gateway.config.config")
local apiGroupDao = require("api_gateway.dao.api_group")
local apiDao = require("api_gateway.dao.api")

local apiGroupRouter = lor:Router()

local RETURN_CODE = {
    SUCCESS = 0,
    WRONG_POST_DATA = 10,
    APIGROUP_ID_INVALID = 20,
    APIGROUP_QUERY_FAIL = 30,
    APIGROUP_DELETE_FAIL = 40,
    APIGROUP_CREATE_FAIL = 50,
    APIGROUP_DELETE_APIS_FAIL = 60, 
    APIGROUP_QUERY_APIS_FAIL = 70, 
}

local function createApiGroup(req, res, next)
    local retObj = {}

    local inputObj = nil

    local ok, decodedObj = pcall(cjson.decode, req.body_raw)
    if not ok then
        retObj.code = RETURN_CODE.WRONG_POST_DATA
        retObj.msg = "post data is not a valid json"
        inputObj = nil
    else
        inputObj = decodedObj
    end

    if inputObj then
        -- validate post data
        if not inputObj.name or not inputObj.base_path then
            retObj.code = RETURN_CODE.WRONG_POST_DATA
            retObj.msg = "name and base_path fields are mandatory"
            inputObj = nil
        end
    end

    if inputObj then
        local ok, apiGroupObj = apiGroupDao.createApiGroup(inputObj)
        if not ok then
            retObj.code = RETURN_CODE.APIGROUP_CREATE_FAIL
            retObj.msg = apiGroupObj -- second parameter is error msg when error occur 
        else
            retObj.code = RETURN_CODE.SUCCESS
            retObj.msg = "success"
            retObj.data = apiGroupObj
        end
    end

    res:json(retObj, true)
end

local function getApiGroupById(req, res, next)
    local retObj = {}
    local apiGroupId = tonumber(req.params.id)
    if not apiGroupId then
        retObj.code = RETURN_CODE.APIGROUP_ID_INVALID
        retObj.msg = "apiGroupId is not valid"
    else
        local ok, apiGroupObj = apiGroupDao.getApiGroupById(apiGroupId)
        if not ok then
            retObj.code = RETURN_CODE.APIGROUP_QUERY_FAIL
            retObj.msg = apiGroupObj -- second parameter is error msg when error occur 
        else
            retObj.code = RETURN_CODE.SUCCESS
            retObj.msg = "success"
            retObj.data = apiGroupObj
        end
    end
    res:json(retObj, true)
end

local function getApiGroupByName(req, res, next)
    local retObj = {}
    local roleName = req.params.name

    local ok, apiGroupObj = apiGroupDao.getApiGroupByName(roleName)
    if not ok then
        retObj.code = RETURN_CODE.APIGROUP_QUERY_FAIL
        retObj.msg = apiGroupObj -- second parameter is error msg when error occur 
    else
        retObj.code = RETURN_CODE.SUCCESS
        retObj.msg = "success"
        retObj.data = apiGroupObj
    end

    res:json(retObj, true)
end

local function updateApiGroupById(req, res, next)
    local retObj = {}
    local apiGroupId = tonumber(req.params.id)
    if not apiGroupId then
        retObj.code = RETURN_CODE.APIGROUP_ID_INVALID
        retObj.msg = "apiGroupId is not valid"
    else
        local inputObj = nil
        local ok, decodedObj = pcall(cjson.decode, req.body_raw)
        if not ok then
            retObj.code = RETURN_CODE.WRONG_POST_DATA
            retObj.msg = "post data is not a valid json"
            inputObj = nil
        else
            inputObj = decodedObj
            inputObj.id = apiGroupId
        end

        if inputObj then
            local ok, apiGroupObj = apiGroupDao.getApiGroupById(apiGroupId)
            if not ok then
                retObj.code = RETURN_CODE.APIGROUP_QUERY_FAIL
                retObj.msg = apiGroupObj -- second parameter is error msg when error occur 
            else
                local ok, msg = apiGroupDao.updateApiGroup(inputObj)
                if not ok then
                    retObj.code = RETURN_CODE.APIGROUP_QUERY_FAIL
                    retObj.msg = msg
                else
                    retObj.code = RETURN_CODE.SUCCESS
                    retObj.msg = "success"
                end
            end
        end
    end
    res:json(retObj, true)
end

local function deleteApiGroupById(req, res, next)
    local retObj = {}
    local apiGroupId = tonumber(req.params.id)
    if not apiGroupId then
        retObj.code = RETURN_CODE.APIGROUP_ID_INVALID
        retObj.msg = "apiGroupId is not valid"
    else
        local ok, apiGroupObj = apiGroupDao.getApiGroupById(apiGroupId)
        if not ok then
            retObj.code = RETURN_CODE.APIGROUP_QUERY_FAIL
            retObj.msg = apiGroupObj -- second parameter is error msg when error occur 
        else
            local ok, apiGroupObj = apiGroupDao.deleteApiGroupById(apiGroupId)
            if not ok then
                retObj.code = RETURN_CODE.APIGROUP_DELETE_FAIL
                retObj.msg = apiGroupObj -- second parameter is error msg when error occur 
            else
                retObj.code = RETURN_CODE.SUCCESS
                retObj.msg = "success"
            end
        end
    end
    res:json(retObj, true)
end

local function oas3import(req, res, next)
    local retObj = {}
    local groupId = tonumber(req.params.id)
    if not groupId then
        retObj.code = RETURN_CODE.APIGROUP_ID_INVALID
        retObj.msg = "apiGroupId is not valid"
    else
        local inputObj = nil
        local ok, decodedObj = pcall(cjson.decode, util.getBodyData())
        if not ok then
            retObj.code = RETURN_CODE.WRONG_POST_DATA
            retObj.msg = "post data is not a valid json"
            inputObj = nil
        else
            inputObj = decodedObj
        end

       local ok, apiGroupObj = apiGroupDao.getApiGroupById(groupId)
        if not ok then
            retObj.code = RETURN_CODE.APIGROUP_QUERY_FAIL
            retObj.msg = apiGroupObj -- second parameter is error msg when error occur 
            inputObj = nil
        end 

        if inputObj then
            retObj.code, retObj.msg = oas3util.oas3_json_import(util.getBodyData(), config.db_file, groupId)
            njt.log(njt.ERR, retObj.code, retObj.msg)
        end
    end

    res:json(retObj, true)
end

local function getApisInGroupById(req, res, next)
    local retObj = {}
    local apiGroupId = tonumber(req.params.id)
    if not apiGroupId then
        retObj.code = RETURN_CODE.APIGROUP_ID_INVALID
        retObj.msg = "apiGroupId is not valid"
    else
        local ok, apiGroupObj = apiGroupDao.getApiGroupById(apiGroupId)
        if not ok then
            retObj.code = RETURN_CODE.APIGROUP_QUERY_FAIL
            retObj.msg = apiGroupObj -- second parameter is error msg when error occur 
        else
            local ok, apisObj = apiGroupDao.getApisInGroupById(apiGroupId)
            if not ok then
                retObj.code = RETURN_CODE.APIGROUP_QUERY_APIS_FAIL
                retObj.msg = apiGroupObj -- second parameter is error msg when error occur 
            else
                retObj.code = 0
                retObj.msg = "success"
                retObj.data = apisObj
            end
        end
    end
    -- data is apis array, it should be return as array
    res:json(retObj, false)
end

apiGroupRouter:post("/api_groups", createApiGroup)
apiGroupRouter:get("/api_groups/:id", getApiGroupById)
apiGroupRouter:get("/api_groups/name/:name", getApiGroupByName)
apiGroupRouter:put("/api_groups/:id", updateApiGroupById)
apiGroupRouter:delete("/api_groups/:id", deleteApiGroupById)
apiGroupRouter:post("/api_groups/:id/oas3", oas3import)
apiGroupRouter:get("/api_groups/:id/apis", getApisInGroupById)

return apiGroupRouter
