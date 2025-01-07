local _M = {}

local cjson = require("cjson")
local split = require("util.split")
local tokenLib = require("njt.token")
local util = require("api_gateway.utils.util")
local base = require("api_gateway.access.base")
local userDao = require("api_gateway.dao.user")
local apiGroupDao = require("api_gateway.dao.api_group")
local config = require("api_gateway.config.config")
local objCache = require("api_gateway.utils.obj_cache")

local RETURN_CODE = {
    SUCCESS = 0,
    PARAM_USERNAME_NOT_FOUND = 10,
    PARAM_PASSWORD_NOT_FOUND = 20, 
    USER_QUERY_FAIL = 30,
    APIGROUP_QUERY_FAIL = 40 
}

function _M.checkUserName(apiObj, paramName)
    local retObj = {}
    local args = njt.req.get_uri_args()

    local username = args[paramName]

    if not username or username == "" then
        retObj.code = RETURN_CODE.PARAM_USERNAME_NOT_FOUND
        retObj.msg = "username not found in url query parameter"
        njt.status = njt.HTTP_UNAUTHORIZED
        njt.say(cjson.encode(retObj))
        return njt.exit(njt.status)
    end

    -- get token from session
    local token_key = "param_username_token_" .. username
    local rc, tv_str = tokenLib.token_get(token_key)

    local refresh_token = args["refresh_token"] or args["refreshToken"]
    if refresh_token and string.lower(tostring(refresh_token)) == "true" then
        tv_str = ""
    end

    if rc ~= 0 or not tv_str or tv_str == "" then
        -- query user/roles and set tokens
        local ok, userObj = userDao.getUserByName(username)
        if not ok then
            retObj.code = RETURN_CODE.USER_QUERY_FAIL
            retObj.msg = userObj -- second parameter is error msg when error occur
            njt.status = njt.HTTP_UNAUTHORIZED
            njt.say(cjson.encode(retObj))
            return njt.exit(njt.status)
        else
            local tv = {} -- token value
            tv.u = userObj.id
            -- set token into session
            local ok, rolesObj = userDao.getUserRoleRel(userObj.id)
            if ok then
                tv.r = rolesObj.roles
                tv_str = cjson.encode(tv)
                local tv_str_to_be_set = tv_str
                -- if token value's length is more than 512 bytes, will get roles later 
                if string.len(tv_str_to_be_set) > 512 then
                    tv.r = nil
                    tv_str_to_be_set = cjson.encode(tv)
                end
                tokenLib.token_set(token_key, tv_str_to_be_set, config.token_lifetime)
            end
        end
    end

    base.verifyToken(tv_str, apiObj)
end

function _M.checkUserNameAndPasswd(apiObj, userId, pwd)
    local retObj = {}
    local args = njt.req.get_uri_args()

    local username = args[userId]
    local password = args[pwd] or ""

    if not username or username == "" then
        retObj.code = RETURN_CODE.PARAM_USERNAME_NOT_FOUND
        retObj.msg = userId .. " not found in url query parameter"
        njt.status = njt.HTTP_UNAUTHORIZED
        njt.say(cjson.encode(retObj))
        return njt.exit(njt.status)
    end
    if not password or password == "" then
        retObj.code = RETURN_CODE.PARAM_PASSWORD_NOT_FOUND
        retObj.msg = pwd .. " not found in url query parameter"
        njt.status = njt.HTTP_UNAUTHORIZED
        njt.say(cjson.encode(retObj))
        return njt.exit(njt.status)
    end

    local name_and_domain, count = split.split_string(username, "@")
    -- if username doesn't include domain , try to add domain from api_group 
    if count == 1  then
        local ok, apiGroupObj = objCache.getApiGroupById(apiObj.group_id)
        if not ok then
            retObj.code = RETURN_CODE.APIGROUP_QUERY_FAIL
            retObj.msg = apiGroupObj -- second parameter is error msg when error occur 
            njt.status = njt.HTTP_UNAUTHORIZED
            njt.say(cjson.encode(retObj))
            return njt.exit(njt.status)
        else
            if apiGroupObj.domain and apiGroupObj.domain ~= "" then
                username = username .. "@" .. apiGroupObj.domain
            end
        end
    end
    -- get token from session
    local token_key = "param_username_token_" .. username .. password
    local rc, tv_str = tokenLib.token_get(token_key)

    local refresh_token = args["refresh_token"] or args["refreshToken"]
    if refresh_token and string.lower(tostring(refresh_token)) == "true" then
        tv_str = ""
    end

    if rc ~= 0 or not tv_str or tv_str == "" then
        -- query user/roles and set tokens
        local encryptedPassword = util.encryptPassword(password)
        local ok, userObj = userDao.getUserByNameAndPassword(username, encryptedPassword)
        if not ok then
            retObj.code = RETURN_CODE.USER_QUERY_FAIL
            retObj.msg = "can't get user using parameters: " .. username .. " / ".. password 
            njt.status = njt.HTTP_UNAUTHORIZED
            njt.say(cjson.encode(retObj))
            return njt.exit(njt.status)
        else
            local tv = {} -- token value
            tv.u = userObj.id
            -- set token into session
            local ok, rolesObj = userDao.getUserRoleRel(userObj.id)
            if ok then
                tv.r = rolesObj.roles
                tv_str = cjson.encode(tv)
                local tv_str_to_be_set = tv_str
                -- if token value's length is more than 512 bytes, will get roles later 
                if string.len(tv_str_to_be_set) > 512 then
                    tv.r = nil
                    tv_str_to_be_set = cjson.encode(tv)
                end
                tokenLib.token_set(token_key, tv_str_to_be_set, config.token_lifetime)
            end
        end
    end

    base.verifyToken(tv_str, apiObj)
end

function _M.check(apiObj, grantModeObj)
    local cookie_name = grantModeObj.properties
    -- 直接使用用户名做权限验证, 非标准方式，并且没有安全性，不建议使用
    if cookie_name and string.lower(cookie_name) == "username" then
        return _M.checkUserName(apiObj, cookie_name)
    end
    -- 直接使用用户名, 密码做权限验证, 非标准方式，并且没有安全性，不建议使用
    if cookie_name and cookie_name == "userId" then
        return _M.checkUserNameAndPasswd(apiObj, "userId", "pwd")
    end

    local args = njt.req.get_uri_args()
    local token = njt.var["cookie_" .. cookie_name] or args[cookie_name]

    local retObj = {}
    -- get token from session
    local rc, tv_str = tokenLib.token_get(token)
    if rc ~= 0 or not tv_str or tv_str == "" then
        retObj.code = RETURN_CODE.AUTH_TOKEN_NOT_VALID
        retObj.msg = "token is not valid"
        njt.status = njt.HTTP_UNAUTHORIZED
        njt.say(cjson.encode(retObj))
        return njt.exit(njt.status)
    end

    base.verifyToken(tv_str, apiObj)
end

return _M
