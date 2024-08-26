local _M={}

local cjson=require("cjson")
local util=require("api_gateway.utils.util")
local apiDao=require("api_gateway.dao.api")

local RETURN_CODE = {
    SUCCESS = 0,
    API_ACCESS_DENY = 403,
}

function _M.verifyToken(tv_str, apiObj)
    local retObj={}
    local rc, tokenRoles = util.getRolesFromToken(tv_str) 
    if rc ~= njt.HTTP_OK then
        retObj.code = rc
        retObj.msg = tokenRoles -- if err, second field is the error message
        njt.status = rc
        njt.say(cjson.encode(retObj))
        return njt.exit(njt.rc)
    end

    local ok, apiRolesObj = apiDao.getApiRoleRel(apiObj.id)
    if not ok or #apiRolesObj.roles == 0  then 
        return RETURN_CODE.API_ACCESS_DENY, "API access is not allowed"
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