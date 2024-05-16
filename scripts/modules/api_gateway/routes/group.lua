local lor = require("lor.index")
local cjson = require("cjson")
local util = require("api_gateway.utils.util")

local groupRouter = lor:Router()
local groupDao = require("api_gateway.dao.group")
local roleDao = require("api_gateway.dao.role")

local RETURN_CODE = {
    SUCCESS = 0,
    WRONG_POST_DATA = 10,
    GROUP_ID_INVALID = 20,
    GROUP_QUERY_FAIL = 30,
    GROUP_DELETE_FAIL = 40,
    GROUP_CREATE_FAIL = 50, 
    GROUP_ROLE_REL_UPDATE_FAIL =60
}

local function createGroup(req, res, next)
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
        if not inputObj.name then
            retObj.code = RETURN_CODE.WRONG_POST_DATA
            retObj.msg = "name field is mandatory"
            inputObj = nil
        end
    end

    if inputObj then
        local ok, groupObj = groupDao.createGroup(inputObj)
        if not ok then
            retObj.code = RETURN_CODE.GROUP_CREATE_FAIL
            retObj.msg = groupObj -- second parameter is error msg when error occur 
        else
            retObj.code = RETURN_CODE.SUCCESS
            retObj.msg = "success"
            retObj.data = groupObj
        end
    end

    res:json(retObj, true)
end

local function getGroupById(req, res, next)
    local retObj = {}
    local groupId = tonumber(req.params.id)
    if not groupId then
        retObj.code = RETURN_CODE.GROUP_ID_INVALID
        retObj.msg = "groupId is not valid"
    else
        local ok, groupObj = groupDao.getGroupById(groupId)
        if not ok then
            retObj.code = RETURN_CODE.GROUP_QUERY_FAIL
            retObj.msg = groupObj -- second parameter is error msg when error occur 
        else
            retObj.code = RETURN_CODE.SUCCESS
            retObj.msg = "success"
            retObj.data = groupObj
        end
    end
    res:json(retObj, true)
end

local function getGroupByName(req, res, next)
    local retObj = {}
    local groupName = req.params.name

    local ok, groupObj = groupDao.getGroupByName(groupName)
    if not ok then
        retObj.code = RETURN_CODE.GROUP_QUERY_FAIL
        retObj.msg = groupObj -- second parameter is error msg when error occur 
    else
        retObj.code = RETURN_CODE.SUCCESS
        retObj.msg = "success"
        retObj.data = groupObj
    end

    res:json(retObj, true)
end

local function updateGroupById(req, res, next)
    local retObj = {}
    local groupId = tonumber(req.params.id)
    if not groupId then
        retObj.code = RETURN_CODE.GROUP_ID_INVALID
        retObj.msg = "groupId is not valid"
    else
        local inputObj = nil
        local ok, decodedObj = pcall(cjson.decode, req.body_raw)
        if not ok then
            retObj.code = RETURN_CODE.WRONG_POST_DATA
            retObj.msg = "post data is not a valid json"
            inputObj = nil
        else
            inputObj = decodedObj
            inputObj.id = groupId
        end

        if inputObj then
            local ok, groupObj = groupDao.getGroupById(groupId)
            if not ok then
                retObj.code = RETURN_CODE.GROUP_QUERY_FAIL
                retObj.msg = groupObj -- second parameter is error msg when error occur 
            else
                local ok, msg = groupDao.updateGroup(inputObj)
                if not ok then
                    retObj.code = RETURN_CODE.GROUP_QUERY_FAIL
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

local function deleteGroupById(req, res, next)
    local retObj = {}
    local groupId = tonumber(req.params.id)
    if not groupId then
        retObj.code = RETURN_CODE.GROUP_ID_INVALID
        retObj.msg = "groupId is not valid"
    else
        local ok, groupObj = groupDao.getGroupById(groupId)
        if not ok then
            retObj.code = RETURN_CODE.GROUP_QUERY_FAIL
            retObj.msg = groupObj -- second parameter is error msg when error occur 
        else
            local ok, groupObj = groupDao.deleteGroupById(groupId)
            if not ok then
                retObj.code = RETURN_CODE.GROUP_DELETE_FAIL
                retObj.msg = groupObj -- second parameter is error msg when error occur 
            else
                retObj.code = RETURN_CODE.SUCCESS
                retObj.msg = "success"
            end
        end
    end
    res:json(retObj, true)
end

-- 组及角色的关系，目前采用全量覆盖方式，数据库中的记录会使用提交的报文进行覆盖
local function updateUserGroupRoleRel(req, res, next)
    local retObj = {}
    local groupId = tonumber(req.params.id)
    if not groupId then
        retObj.code = RETURN_CODE.GROUP_ID_INVALID
        retObj.msg = "groupId is not valid"
    else
        local inputObj = nil
        local ok, decodedObj = pcall(cjson.decode, req.body_raw)
        if not ok then
            retObj.code = RETURN_CODE.WRONG_POST_DATA
            retObj.msg = "post data is not a valid json"
            inputObj = nil
        else
            inputObj = decodedObj
            inputObj.id = groupId
        end

        if inputObj then
            local ok, groupObj = groupDao.getGroupById(groupId)
            if not ok then
                retObj.code = RETURN_CODE.GROUP_QUERY_FAIL
                retObj.msg = groupObj -- second parameter is error msg when error occur 
            else
                -- check roleId
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
                        local ok, roleObj = roleDao.getRoleById(tonumber(v)) 
                        if not ok then
                            validateSucc = false
                            retObj.code = RETURN_CODE.WRONG_POST_DATA
                            retObj.msg = "roleId "..tostring(v).. " is not existed"
                            break
                        end 
                    end
                end
                
                if validateSucc then
                    local ok, msg = groupDao.updateUserGroupRoleRel(inputObj)
                    if not ok then
                        retObj.code = RETURN_CODE.GROUP_ROLE_REL_UPDATE_FAIL
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

local function getUserGroupRoleRel(req, res, next)
    local retObj = {}
    local groupId = tonumber(req.params.id)
    if not groupId then
        retObj.code = RETURN_CODE.GROUP_ID_INVALID
        retObj.msg = "groupId is not valid"
    else
        local ok, groupObj = groupDao.getGroupById(groupId)
        if not ok then
            retObj.code = RETURN_CODE.GROUP_QUERY_FAIL
            retObj.msg = groupObj -- second parameter is error msg when error occur 
        else
            local ok, groupObj = groupDao.getUserGroupRoleRel(groupId)
            if not ok then
                retObj.code = RETURN_CODE.GROUP_QUERY_FAIL
                retObj.msg = groupObj -- second parameter is error msg when error occur 
            else
                retObj.code = RETURN_CODE.SUCCESS
                retObj.msg = "success"
                retObj.data = groupObj
            end
        end
    end
    -- groups could be empty array
    res:json(retObj, false)
end

groupRouter:post("/groups", createGroup)
groupRouter:get("/groups/:id", getGroupById)
groupRouter:get("/groups/name/:name", getGroupByName)
groupRouter:put("/groups/:id", updateGroupById)
groupRouter:delete("/groups/:id", deleteGroupById)

groupRouter:put("/groups/:id/roles", updateUserGroupRoleRel)
groupRouter:get("/groups/:id/roles", getUserGroupRoleRel)


return groupRouter
