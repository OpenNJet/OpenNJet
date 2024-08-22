local _M = {}

local cjson=require("cjson")
local authDao = require("api_gateway.dao.auth")
local userDao = require("api_gateway.dao.user")
local lorUtils=require("lor.lib.utils.utils")
local tokenLib=require("njt.token")
local constValue=require("api_gateway.config.const")
local base=require("api_gateway.access.base")

local RETURN_CODE = {
    SUCCESS = 0,
    AUTH_TOKEN_NOT_FOUND = 10,
    AUTH_TOKEN_NOT_VALID = 20,
    USER_NOT_FOUND = 30, 
}

function _M.check(apiObj, grantModeObj) 
    local retObj={}
    
    njt.log(njt.DEBUG, "in rbac implementation's check")
    -- check bearer token
    local authToken = njt.req.get_headers()["Authorization"] 
    if not authToken then
        retObj.code = RETURN_CODE.AUTH_TOKEN_NOT_EXISTED
        retObj.msg = "Authorization token is not found in Header"
        njt.status = njt.HTTP_UNAUTHORIZED
        njt.say(cjson.encode(retObj))
        return njt.exit(njt.status)
    end
    local tokenFields = lorUtils.split(authToken, " ")
    if #tokenFields ~= 2 or string.lower(tokenFields[1]) ~= "bearer" then
        retObj.code = RETURN_CODE.AUTH_TOKEN_NOT_VALID
        retObj.msg = "bearer token format is not correct"
        njt.status = njt.HTTP_UNAUTHORIZED
        njt.say(cjson.encode(retObj))
        return njt.exit(njt.status)
    end

    -- get token from session
    local rc, tv_str=tokenLib.token_get(tokenFields[2])
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
