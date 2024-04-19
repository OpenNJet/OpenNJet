local lor = require("lor.index")
local cjson = require("cjson")
local util = require("api_gateway.utils.util")

local userRouter = lor:Router()
local userDao = require("api_gateway.dao.user")
local groupDao = require("api_gateway.dao.group")

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
        if not inputObj.name or not inputObj.password then
            retObj.code = RETURN_CODE.WRONG_POST_DATA
            retObj.msg = "name and password fields are mandatory"
            inputObj = nil
        end
        if inputObj.email and not util.checkEmail(inputObj.email) then
            retObj.code = RETURN_CODE.WRONG_POST_DATA
            retObj.msg = "email is not valid"
            inputObj = nil
        end
        if inputObj.mobile and not util.checkMobile(inputObj.mobile) then
            retObj.code = RETURN_CODE.WRONG_POST_DATA
            retObj.msg = "mobile is not valid"
            inputObj = nil
        end
    end

    if inputObj then
        -- encrypt password
        inputObj.password = util.encryptPassword(inputObj.password)
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
                    for _,v in ipairs(inputObj.groups) do
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
                            retObj.msg = "groupId "..tostring(v).. " is not existed"
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
userRouter:put("/users/:id", updateUserById)
userRouter:delete("/users/:id", deleteUserById)
userRouter:get("/users/name/:name", getUserByName)

userRouter:put("/users/:id/groups", updateUserGroupRel)
userRouter:get("/users/:id/groups", getUserGroupRel)

return userRouter
