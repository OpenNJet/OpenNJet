local lor = require("lor.index")
local cjson = require("cjson")
local util = require("api_gateway.utils.util")

local userRouter = lor:Router()
local userDao = require("api_gateway.dao.user")
local groupDao = require("api_gateway.dao.group")
local objCache = require("api_gateway.utils.obj_cache")

local ICONS_LOCATION = "/icons/"

local RETURN_CODE = {
    SUCCESS = 0,
    WRONG_POST_DATA = 10,
    USER_ID_INVALID = 20,
    USER_QUERY_FAIL = 30,
    USER_DELETE_FAIL = 40,
    USER_CREATE_FAIL = 50,
    USER_GROUP_REL_UPDATE_FAIL = 60
}

local function getUserById(req, res, next)
    local retObj = {}
    local userId = tonumber(req.params.id)
    if not userId then
        retObj.code = RETURN_CODE.USER_ID_INVALID
        retObj.msg = "userId is not valid"
    else
        local ok, userObj = userDao.getUserById(userId)
        if not ok then
            retObj.code = RETURN_CODE.USER_QUERY_FAIL
            retObj.msg = userObj -- second parameter is error msg when error occur 
        else
            retObj.code = RETURN_CODE.SUCCESS
            retObj.msg = "success"
            retObj.data = userObj
        end
    end
    res:json(retObj, true)
end

local function getAllUsers(req, res, next)
    local retObj = {}
    -- Get query parameters
    local ps = req.query.pageSize
    local pn = req.query.pageNum

    local ps_i = tonumber(ps) or 10
    local pn_i = tonumber(pn) or 1

    local ok, userObj = userDao.getAllUsers(ps_i, pn_i)
    if not ok then
        retObj.code = RETURN_CODE.USER_QUERY_FAIL
        retObj.msg = userObj -- second parameter is error msg when error occur 
    else
        retObj.code = RETURN_CODE.SUCCESS
        retObj.msg = "success"
        retObj.data = userObj
    end

    res:json(retObj, true)
end

local function getFilterUsers(req, res, next)
    local retObj = {}
    -- Get query parameters
    local ps = req.query.pageSize
    local pn = req.query.pageNum

    local ps_i = tonumber(ps) or 10
    local pn_i = tonumber(pn) or 1

    local name = req.query.name or ""
    local domain = req.query.domain or ""

    local user_name = name .. "%".. domain

    local ok, userObj = userDao.getFilterUsers(user_name, ps_i, pn_i)
    if not ok then
        retObj.code = RETURN_CODE.USER_QUERY_FAIL
        retObj.msg = userObj -- second parameter is error msg when error occur 
    else
        retObj.code = RETURN_CODE.SUCCESS
        retObj.msg = "success"
        retObj.data = userObj
    end

    res:json(retObj, true)
end

local function getDomainForUsers(req, res, next)
    local retObj = {}

    local ok, domainObj = userDao.getDomainForUsers()
    if not ok then
        retObj.code = RETURN_CODE.USER_QUERY_FAIL
        retObj.msg = domainObj -- second parameter is error msg when error occur 
    else
        retObj.code = RETURN_CODE.SUCCESS
        retObj.msg = "success"
        retObj.data = domainObj
    end

    res:json(retObj, true)
end

local function deleteUserById(req, res, next)
    local retObj = {}
    local userId = tonumber(req.params.id)
    if not userId then
        retObj.code = RETURN_CODE.USER_ID_INVALID
        retObj.msg = "userId is not valid"
    else
        local ok, userObj = userDao.getUserById(userId)
        if not ok then
            retObj.code = RETURN_CODE.USER_QUERY_FAIL
            retObj.msg = userObj -- second parameter is error msg when error occur 
        else
            local ok, userObj = userDao.deleteUserById(userId)
            if not ok then
                retObj.code = RETURN_CODE.USER_DELETE_FAIL
                retObj.msg = userObj -- second parameter is error msg when error occur 
            else
                retObj.code = RETURN_CODE.SUCCESS
                retObj.msg = "success"
            end
        end
    end
    res:json(retObj, true)
end

local function updateUserById(req, res, next)
    local retObj = {}
    local userId = tonumber(req.params.id)
    if not userId then
        retObj.code = RETURN_CODE.USER_ID_INVALID
        retObj.msg = "userId is not valid"
    else
        local inputObj = nil
        local ok, decodedObj = pcall(cjson.decode, req.body_raw)
        if not ok then
            retObj.code = RETURN_CODE.WRONG_POST_DATA
            retObj.msg = "post data is not a valid json"
            inputObj = nil
        else
            inputObj = decodedObj
            inputObj.id = userId
        end

        if inputObj then
            local ok, userObj = userDao.getUserById(userId)
            if not ok then
                retObj.code = RETURN_CODE.USER_QUERY_FAIL
                retObj.msg = userObj -- second parameter is error msg when error occur 
            else
                if inputObj.password then
                    -- encrypt password
                    inputObj.password = util.encryptPassword(inputObj.password)
                end
                local ok, msg = userDao.updateUser(inputObj)
                if not ok then
                    retObj.code = RETURN_CODE.USER_QUERY_FAIL
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

local function getUserByName(req, res, next)
    local retObj = {}
    local userName = req.params.name

    local ok, userObj = userDao.getUserByName(userName)
    if not ok then
        retObj.code = RETURN_CODE.USER_QUERY_FAIL
        retObj.msg = userObj -- second parameter is error msg when error occur 
    else
        retObj.code = RETURN_CODE.SUCCESS
        retObj.msg = "success"
        retObj.data = userObj
    end

    res:json(retObj, true)
end

local function  getAllApiGroupsForUser(req, res, next)
    local retObj = {}
    local userName = req.params.name
    -- Get query parameters
    local ps = req.query.pageSize
    local pn = req.query.pageNum

    local ps_i = tonumber(ps) or 10
    local pn_i = tonumber(pn) or 1

    local ok, appsObj = userDao.getAllApiGroupsForUser(userName, ps_i, pn_i)
    if not ok then
        retObj.code = RETURN_CODE.USER_QUERY_FAIL
        retObj.msg = appsObj -- second parameter is error msg when error occur 
    else
        for _, ag in ipairs(appsObj.api_groups) do
            local ok, manifest = objCache.getAppManifest(ag.name)
            if ok and manifest then
                if  manifest.app and manifest.app.icon_file then 
                    local icon_file =  manifest.app.icon_file
                    local icon_ext = icon_file:lower():match("%.(%w+)$")
                    ag.icon_url = ICONS_LOCATION ..manifest.app.name.."."..icon_ext
                else 
                    ag.icon_url = ICONS_LOCATION .. "default.png"
                end
                ag.server_name = manifest.deployment.server_name or ""
            end
        end

        retObj.code = RETURN_CODE.SUCCESS
        retObj.msg = "success"
        retObj.data = appsObj
    end

    res:json(retObj, true)
end

local function createUser(req, res, next)
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
        if not inputObj.domain or not inputObj.name or not inputObj.password then
            retObj.code = RETURN_CODE.WRONG_POST_DATA
            retObj.msg = "domain, name and password fields are mandatory"
            goto CREATE_USER_FINISH
        end

        if string.find(inputObj.name, "@") then
            retObj.code = RETURN_CODE.WRONG_POST_DATA
            retObj.msg = "name field should not have @ character in it"
            goto CREATE_USER_FINISH
        end

        if inputObj.email and not util.checkEmail(inputObj.email) then
            retObj.code = RETURN_CODE.WRONG_POST_DATA
            retObj.msg = "email is not valid"
            goto CREATE_USER_FINISH
        end
        if inputObj.mobile and not util.checkMobile(inputObj.mobile) then
            retObj.code = RETURN_CODE.WRONG_POST_DATA
            retObj.msg = "mobile is not valid"
            goto CREATE_USER_FINISH
        end
    end

    if inputObj then
        -- encrypt password
        inputObj.password = util.encryptPassword(inputObj.password)
        inputObj.name = inputObj.name .. "@" .. inputObj.domain
        local ok, userObj = userDao.createUser(inputObj)
        if not ok then
            retObj.code = RETURN_CODE.USER_CREATE_FAIL
            retObj.msg = userObj -- second parameter is error msg when error occur 
        else
            retObj.code = RETURN_CODE.SUCCESS
            retObj.msg = "success"
            retObj.data = userObj
        end
    end

    ::CREATE_USER_FINISH::
    res:json(retObj, true)
end

-- 用户及组的关系，目前采用全量覆盖方式，数据库中的记录会使用提交的报文进行覆盖
local function updateUserGroupRel(req, res, next)
    local retObj = {}
    local userId = tonumber(req.params.id)
    if not userId then
        retObj.code = RETURN_CODE.USER_ID_INVALID
        retObj.msg = "userId is not valid"
    else
        local inputObj = nil
        local ok, decodedObj = pcall(cjson.decode, req.body_raw)
        if not ok then
            retObj.code = RETURN_CODE.WRONG_POST_DATA
            retObj.msg = "post data is not a valid json"
            inputObj = nil
        else
            inputObj = decodedObj
            inputObj.id = userId
        end

        if inputObj then
            local ok, userObj = userDao.getUserById(userId)
            if not ok then
                retObj.code = RETURN_CODE.USER_QUERY_FAIL
                retObj.msg = userObj -- second parameter is error msg when error occur 
            else
                -- check groupId
                local validateSucc = true
                if not inputObj.groups or not util.isArray(inputObj.groups) then
                    validateSucc = false
                    retObj.code = RETURN_CODE.WRONG_POST_DATA
                    retObj.msg = "groups is mandatory"
                else
                    for _, v in ipairs(inputObj.groups) do
                        if not tonumber(v) then
                            validateSucc = false
                            retObj.code = RETURN_CODE.WRONG_POST_DATA
                            retObj.msg = "element in groups should be an integer"
                            break
                        end
                        local ok, groupObj = groupDao.getGroupById(tonumber(v))
                        if not ok then
                            validateSucc = false
                            retObj.code = RETURN_CODE.WRONG_POST_DATA
                            retObj.msg = "groupId " .. tostring(v) .. " is not existed"
                            break
                        end
                    end
                end

                if validateSucc then
                    local ok, msg = userDao.updateUserGroupRel(inputObj)
                    if not ok then
                        retObj.code = RETURN_CODE.USER_GROUP_REL_UPDATE_FAIL
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

local function getUserGroupRel(req, res, next)
    local retObj = {}
    local userId = tonumber(req.params.id)
    if not userId then
        retObj.code = RETURN_CODE.USER_ID_INVALID
        retObj.msg = "userId is not valid"
    else
        local ok, userObj = userDao.getUserById(userId)
        if not ok then
            retObj.code = RETURN_CODE.USER_QUERY_FAIL
            retObj.msg = userObj -- second parameter is error msg when error occur 
        else
            local ok, userObj = userDao.getUserGroupRel(userId)
            if not ok then
                retObj.code = RETURN_CODE.USER_QUERY_FAIL
                retObj.msg = userObj -- second parameter is error msg when error occur 
            else
                retObj.code = RETURN_CODE.SUCCESS
                retObj.msg = "success"
                retObj.data = userObj
            end
        end
    end
    -- groups could be empty array
    res:json(retObj, false)
end

userRouter:post("/users", createUser)
userRouter:get("/users/:id", getUserById)
userRouter:get("/users/list/all",getAllUsers)
userRouter:get("/users/list/filter",getFilterUsers)
userRouter:get("/users/list/domain",getDomainForUsers)
userRouter:put("/users/:id", updateUserById)
userRouter:delete("/users/:id", deleteUserById)
userRouter:get("/users/name/:name", getUserByName)
userRouter:get("/users/name/:name/api_groups", getAllApiGroupsForUser)

userRouter:put("/users/:id/groups", updateUserGroupRel)
userRouter:get("/users/:id/groups", getUserGroupRel)

return userRouter
