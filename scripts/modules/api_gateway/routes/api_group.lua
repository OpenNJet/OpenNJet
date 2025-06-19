local lor = require("lor.index")
local cjson = require("cjson")
local util = require("api_gateway.utils.util")
local oas3util = require("api_gateway.utils.oas3_import")
local config = require("api_gateway.config.config")
local dbConfig = require("api_gateway.config.db")
local apiGroupDao = require("api_gateway.dao.api_group")
local apiDao = require("api_gateway.dao.api")
local roleDao =  require("api_gateway.dao.role")
local constValue =  require("api_gateway.config.const")
local objCache = require("api_gateway.utils.obj_cache")

local apiGroupRouter = lor:Router()

local RETURN_CODE = {
    SUCCESS = 0,
    WRONG_POST_DATA = 10,
    APIGROUP_ID_INVALID = 20,
    APIGROUP_NAME_INVALID = 21,
    APIGROUP_QUERY_FAIL = 30,
    APIGROUP_DELETE_FAIL = 40,
    APIGROUP_CREATE_FAIL = 50,
    APIGROUP_DELETE_APIS_FAIL = 60, 
    APIGROUP_QUERY_APIS_FAIL = 70, 
    APIGROUP_NOT_ALLOWED = 80, 
    API_ID_INVALID = 90,
    API_QUERY_INVALID = 100,
    ROLE_API_REL_UPDATE_FAIL = 110, 
}

local function hasPermissionToInvoke(req, apiGroupUserId)
     local req_user_id= tonumber(njt.req.get_headers()[constValue.HEADER_USER_ID])
     njt.log(njt.DEBUG, "req_user_id: ".. tostring(req_user_id).. " apiGroupUserId" .. tostring(apiGroupUserId))
     if req_user_id then
        if req_user_id == apiGroupUserId then
            return true
        else 
            return false
        end
    end
    -- user id is set to header by access by lua code, 
    -- if it is not set, it means we don't need access ctl
    return true
end

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
        inputObj.user_id= njt.req.get_headers()[constValue.HEADER_USER_ID] or ""
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
            if hasPermissionToInvoke(req, apiGroupObj.user_id) then
                retObj.code = RETURN_CODE.SUCCESS
                retObj.msg = "success"
                retObj.data = apiGroupObj
            else 
                retObj.code = RETURN_CODE.APIGROUP_NOT_ALLOWED
                retObj.msg = "query not allowed"
            end
        end
    end
    
    res:json(retObj, true)
end

local function getAllApiGroups(req, res, next)
    local retObj = {}
    -- Get query parameters
    local ps = req.query.pageSize
    local pn = req.query.pageNum

    local ps_i = tonumber(ps) or 10
    local pn_i = tonumber(pn) or 1

    local ok, groupObj = apiGroupDao.getAllApiGroups(ps_i, pn_i)
    if not ok then
        retObj.code = RETURN_CODE.APIGROUP_QUERY_FAIL
        retObj.msg = groupObj -- second parameter is error msg when error occur 
    else
        retObj.code = RETURN_CODE.SUCCESS
        retObj.msg = "success"
        retObj.data = groupObj
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
        if hasPermissionToInvoke(req, apiGroupObj.user_id) then
            retObj.code = RETURN_CODE.SUCCESS
            retObj.msg = "success"
            retObj.data = apiGroupObj
        else 
            retObj.code = RETURN_CODE.APIGROUP_NOT_ALLOWED
            retObj.msg = "query not allowed"
        end
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
                if hasPermissionToInvoke(req, apiGroupObj.user_id) then
                    local ok, msg = apiGroupDao.updateApiGroup(inputObj)
                    if not ok then
                        retObj.code = RETURN_CODE.APIGROUP_QUERY_FAIL
                        retObj.msg = msg
                    else
                        retObj.code = RETURN_CODE.SUCCESS
                        retObj.msg = "success"
                    end
                else 
                    retObj.code = RETURN_CODE.APIGROUP_NOT_ALLOWED
                    retObj.msg = "update not allowed"
                end
            end
        end
    end

    if retObj.code == RETURN_CODE.SUCCESS then
        objCache.clearApiCache()
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
            if hasPermissionToInvoke(req, apiGroupObj.user_id) then
                local ok, apiGroupObj = apiGroupDao.deleteApiGroupById(apiGroupId)
                if not ok then
                    retObj.code = RETURN_CODE.APIGROUP_DELETE_FAIL
                    retObj.msg = apiGroupObj -- second parameter is error msg when error occur 
                else
                    retObj.code = RETURN_CODE.SUCCESS
                    retObj.msg = "success"
                end
            else 
                retObj.code = RETURN_CODE.APIGROUP_NOT_ALLOWED
                retObj.msg = "delete not allowed"
            end
        end
    end

    if retObj.code == RETURN_CODE.SUCCESS then
        objCache.clearApiCache()
    end
    res:json(retObj, true)
end

local function oas3import(req, res, next)
    local retObj = {}
    local groupName = req.params.name
    if groupName == "" then
        retObj.code = RETURN_CODE.APIGROUP_NAME_INVALID
        retObj.msg = "apiGroupName is not valid"
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

       local ok, apiGroupObj = apiGroupDao.getApiGroupByName(groupName)
        if not ok then
            retObj.code = RETURN_CODE.APIGROUP_QUERY_FAIL
            retObj.msg = apiGroupObj -- second parameter is error msg when error occur 
            inputObj = nil
        end 

        if inputObj then
            if hasPermissionToInvoke(req, apiGroupObj.user_id) then
                retObj.code, retObj.msg = oas3util.oas3_json_import(util.getBodyData(), dbConfig.db_file, apiGroupObj.id)
                njt.log(njt.ERR, retObj.code, retObj.msg)
            else 
                retObj.code = RETURN_CODE.APIGROUP_NOT_ALLOWED
                retObj.msg = "import not allowed"
            end
        end
    end

    if retObj.code == RETURN_CODE.SUCCESS then
        objCache.clearApiCache()
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
            if hasPermissionToInvoke(req, apiGroupObj.user_id) then
                local ok, apisObj = apiGroupDao.getApisInGroupById(apiGroupId)
                if not ok then
                    retObj.code = RETURN_CODE.APIGROUP_QUERY_APIS_FAIL
                    retObj.msg = apiGroupObj -- second parameter is error msg when error occur 
                else
                    retObj.code = 0
                    retObj.msg = "success"
                    retObj.data = apisObj
                end
            else 
                retObj.code = RETURN_CODE.APIGROUP_NOT_ALLOWED
                retObj.msg = "query not allowed"
            end
        end
    end
    -- data is apis array, it should be return as array
    res:json(retObj, false)
end

-- 角色与API的关系，目前采用全量覆盖方式，数据库中的记录会使用提交的报文进行覆盖
local function updateRolesInApiById(req, res, next)
    local retObj = {}
    local apiId = tonumber(req.params.id)
    if not apiId then
        retObj.code = RETURN_CODE.API_ID_INVALID
        retObj.msg = "apiId is not valid"
    else
        local inputObj = nil
        local ok, decodedObj = pcall(cjson.decode, req.body_raw)
        if not ok then
            retObj.code = RETURN_CODE.WRONG_POST_DATA
            retObj.msg = "post data is not a valid json"
            inputObj = nil
        else
            inputObj = decodedObj
            inputObj.id = apiId
        end

        if inputObj then
            local ok, apiObj = apiDao.getApiById(apiId)
            if not ok then
                retObj.code = RETURN_CODE.API_QUERY_INVALID
                retObj.msg = apiObj -- second parameter is error msg when error occur 
            else
                -- check apiId
                local validateSucc = true
                if not inputObj.roles or not util.isArray(inputObj.roles) then
                    validateSucc = false
                    retObj.code = RETURN_CODE.WRONG_POST_DATA
                    retObj.msg = "roles is mandatory"
                else
                    for _,v in ipairs(inputObj.roles) do
                        if not tonumber(v) then
                            validateSucc = false
                            retObj.code = RETURN_CODE.WRONG_POST_DATA
                            retObj.msg = "element in roles should be an integer"
                            break
                        end
                        local ok, _ = roleDao.getRoleById(tonumber(v)) 
                        if not ok then
                            validateSucc = false
                            retObj.code = RETURN_CODE.WRONG_POST_DATA
                            retObj.msg = "roldId "..tostring(v).. " is not existed"
                            break
                        end 
                    end
                end
                
                if validateSucc then
                    local ok, msg = apiDao.updateRoleApiRel(inputObj)
                    if not ok then
                        retObj.code = RETURN_CODE.ROLE_API_REL_UPDATE_FAIL
                        retObj.msg = msg
                    else
                        retObj.code = RETURN_CODE.SUCCESS
                        retObj.msg = "success"
                    end
                end
            end
        end
    end
    res:json(retObj, true)
end

local function getRolesInApiById(req, res, next)
    local retObj = {}
    local apiId = tonumber(req.params.id)
    if not apiId then
        retObj.code = RETURN_CODE.API_ID_INVALID
        retObj.msg = "apiId is not valid"
    else
        local ok, apiObj = apiDao.getApiById(apiId)
        if not ok then
            retObj.code = RETURN_CODE.API_QUERY_INVALID
            retObj.msg = apiObj -- second parameter is error msg when error occur 
        else
            local ok, roleObj = apiDao.getRoleApiRel(apiId)
            if not ok then
                retObj.code = RETURN_CODE.API_QUERY_INVALID
                retObj.msg = roleObj -- second parameter is error msg when error occur 
            else
                retObj.code = RETURN_CODE.SUCCESS
                retObj.msg = "success"
                retObj.data = roleObj
            end
        end
    end
    -- groups could be empty array
    res:json(retObj, false)
end


local function updateRolesInApis(req, res, next)
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
        local validateSucc = true
        if not inputObj.roles or not util.isArray(inputObj.roles) or not inputObj.apis or
            not util.isArray(inputObj.apis) then
            validateSucc = false
            retObj.code = RETURN_CODE.WRONG_POST_DATA
            retObj.msg = "apis/roles is mandatory"
        else
            for _, v in ipairs(inputObj.apis) do
                if not tonumber(v) then
                    validateSucc = false
                    retObj.code = RETURN_CODE.WRONG_POST_DATA
                    retObj.msg = "element in apis should be an integer"
                    break
                end
                local ok, _ = apiDao.getApiById(tonumber(v))
                if not ok then
                    validateSucc = false
                    retObj.code = RETURN_CODE.WRONG_POST_DATA
                    retObj.msg = "apiId " .. tostring(v) .. " is not existed"
                    break
                end
            end
            for _, v in ipairs(inputObj.roles) do
                if not tonumber(v) then
                    validateSucc = false
                    retObj.code = RETURN_CODE.WRONG_POST_DATA
                    retObj.msg = "element in roles should be an integer"
                    break
                end
                local ok, _ = roleDao.getRoleById(tonumber(v))
                if not ok then
                    validateSucc = false
                    retObj.code = RETURN_CODE.WRONG_POST_DATA
                    retObj.msg = "roldId " .. tostring(v) .. " is not existed"
                    break
                end
            end
        end

        if validateSucc then
            for _, v in ipairs(inputObj.apis) do
                inputObj.id = tonumber(v)
                local ok, msg = apiDao.updateRoleApiRel(inputObj)
                if not ok then
                    retObj.code = RETURN_CODE.ROLE_API_REL_UPDATE_FAIL
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

apiGroupRouter:post("/api_groups", createApiGroup)
apiGroupRouter:get("/api_groups/:id", getApiGroupById)
apiGroupRouter:get("/api_groups/list/all",getAllApiGroups)
apiGroupRouter:get("/api_groups/name/:name", getApiGroupByName)
apiGroupRouter:put("/api_groups/:id", updateApiGroupById)
apiGroupRouter:delete("/api_groups/:id", deleteApiGroupById)
apiGroupRouter:post("/api_groups/name/:name/oas3", oas3import)
apiGroupRouter:get("/api_groups/:id/apis", getApisInGroupById)
apiGroupRouter:put("/apis/:id/roles", updateRolesInApiById)
apiGroupRouter:get("/apis/:id/roles", getRolesInApiById)
apiGroupRouter:put("/apis_roles", updateRolesInApis)

return apiGroupRouter
