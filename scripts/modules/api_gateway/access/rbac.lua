local _M = {}

local cjson=require("cjson")
local authDao = require("api_gateway.dao.auth")
local userDao = require("api_gateway.dao.user")
local apiDao=require("api_gateway.dao.api")
local lorUtils=require("lor.lib.utils.utils")
local tokenLib=require("njt.token")

local RETURN_CODE = {
    SUCCESS = 0,
    AUTH_TOKEN_NOT_FOUND = 10,
    AUTH_TOKEN_NOT_VALID = 20,
    API_ACCESS_DENY = 30,
    USER_NOT_FOUND = 40, 
}

function _M.check(apiObj) 
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
    local rc, userId=tokenLib.token_get(tokenFields[2])
    if rc ~= 0 then 
        retObj.code = RETURN_CODE.AUTH_TOKEN_NOT_VALID
        retObj.msg = "token is not valid"
        njt.status = njt.HTTP_UNAUTHORIZED
        njt.say(cjson.encode(retObj))
        return njt.exit(njt.status)
    end 
    local ok, rolesObj = userDao.getUserRoleRel(userId)
    if not ok then
        retObj.code = RETURN_CODE.USER_NOT_FOUND
        retObj.msg = "can't found the user in db"
        njt.status = njt.HTTP_UNAUTHORIZED
        njt.say(cjson.encode(retObj))
        return njt.exit(njt.status)
    end
    local tokenRoles = rolesObj.roles
    local ok, apiRolesObj = apiDao.getApiRoleRel(apiObj.id)
    if not ok or #apiRolesObj.roles == 0  then 
        retObj.code = RETURN_CODE.API_ACCESS_DENY
        retObj.msg = "API access is not allowed"
        njt.status = njt.HTTP_FORBIDDEN
        njt.say(cjson.encode(retObj))
        return njt.exit(njt.status)
    end
    local apiGranted = false 
    for _, tokenRole in ipairs(tokenRoles) do
        local tokenRoleId = tonumber(tokenRole)
        if tokenRoleId then 
            for _, apiRoleId in ipairs(apiRolesObj.roles) do
                if tokenRoleId == apiRoleId then
                    apiGranted = true
                    break
                end
            end
        end
    end
    if not apiGranted then
        retObj.code = RETURN_CODE.API_ACCESS_DENY
        retObj.msg = "API access is not allowed"
        njt.status = njt.HTTP_FORBIDDEN
        njt.say(cjson.encode(retObj))
        return njt.exit(njt.status)
    end
end 

return _M 