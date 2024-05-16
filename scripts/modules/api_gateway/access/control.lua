local accessControl = {}
-- class table
local ACCESSCTL = {}

local apiGroupDao = require("api_gateway.dao.api_group")
local apiDao = require("api_gateway.dao.api")
local lorUtils=require("lor.lib.utils.utils")
local cjson = require("cjson")
cjson.encode_escape_forward_slash(false)

local RETURN_CODE = {
    SUCCESS = 0,
    WRONG_CONF_DATA = 10,
    API_GROUP_NOT_FOUND = 20,
    API_GRANT_MODE_NOT_FOUND = 30, 
}

local GRANT_MODES = {
    ALWAYS = 0, 
    RBAC = 1
}

local GRANT_MODE_IMPLEMENT = {
    [1] = "rbac"
}

local function requestPathMatch(uri, base_path, oas3_path)
    local uriFields = lorUtils.split(uri, "/")
    local pathFields = lorUtils.split(base_path..oas3_path, "/")
    if #uriFields ~= #pathFields then
        return false
    end
    -- compare configured api path with request uri，and "{...}" in api define means path parmater
    for i, v in ipairs(uriFields) do
        local match=false
        if lorUtils.start_with(pathFields[i], "{") and lorUtils.end_with(pathFields[i], "}")  then
            match = true
        else 
            if string.lower(pathFields[i]) == string.lower(v) then 
                match = true
            end
        end
        if not match then
            return false
        end
    end

    return true
end

function ACCESSCTL:getApiId(apiGroupId)
    -- apiGroupId is validated in previous step, assume it is correct
    local criteria= string.format(" where group_id = %s and lower(method) = '%s'", tostring(apiGroupId.id), string.lower(njt.req.get_method()))

   local ok, apis = apiDao.getApisByCriteria(criteria)

   if not ok then 
       return false, nil
   end

   for _, api in ipairs(apis) do
      if requestPathMatch(njt.var.uri, self.base_path, api.path) then
        njt.log(njt.DEBUG, "uri:"..njt.var.uri.." got api from db: "..cjson.encode(api))
        return true, api
      end
    end
  
   return false, nil
end

function ACCESSCTL:check()
    local retObj = {}
    if not self.base_path or self.base_path == "" then
        retObj.code = RETURN_CODE.WRONG_CONF_DATA
        retObj.msg = "base_path is empty"
        njt.status = njt.HTTP_FORBIDDEN
        njt.say(cjson.encode(retObj))
        return njt.exit(njt.status)
    end

    -- get app group id
    local ok, apiGroupObj = apiGroupDao.getApiGroupByBasePath(self.base_path)
    if not ok then
        retObj.code = RETURN_CODE.API_GROUP_NOT_FOUND
        retObj.msg = "can't found api group in db using base_path " .. self.base_path
        njt.status = njt.HTTP_FORBIDDEN
        njt.say(cjson.encode(retObj))
        return njt.exit(njt.status)
    end

    --get app id
    local ok, apiObj = self:getApiId(apiGroupObj)
    if not ok then
        retObj.code = RETURN_CODE.API_GROUP_NOT_FOUND
        retObj.msg = "uri '" .. njt.var.uri .. "' with method ".. njt.req.get_method() .. " is not configured"
        njt.status = njt.HTTP_FORBIDDEN
        njt.say(cjson.encode(retObj))
        return njt.exit(njt.status)
    end

    -- get api_grant_mode  
    local ok, grantModes = apiDao.getApiGrantModes(apiObj.id)
    if not ok or #grantModes == 0 then
        retObj.code = RETURN_CODE.API_GRANT_MODE_NOT_FOUND
        retObj.msg = "grant mode is not configured for api '" .. njt.var.uri .. "'"
        njt.status = njt.HTTP_FORBIDDEN
        njt.say(cjson.encode(retObj))
        return njt.exit(njt.status)
    end

    -- base on the grant_mode, create corresponding sevice to do validation, 
    -- right now only first grant_mode is checked
    if grantModes[1] == GRANT_MODES.ALWAYS then
        return 
    end
    local implementation = GRANT_MODE_IMPLEMENT[grantModes[1]] 
    if not implementation then
        retObj.code = RETURN_CODE.API_GRANT_MODE_NOT_FOUND
        retObj.msg = "grand mode ".. tostring(grantModes[1]).." not implemented yet"
        njt.status = njt.HTTP_FORBIDDEN
        njt.say(cjson.encode(retObj))
        return njt.exit(njt.status)
    else 
        local ok, implementObj = pcall(require, "api_gateway.access.".. implementation )
        if not ok then 
            retObj.code = RETURN_CODE.API_GRANT_MODE_NOT_FOUND
            retObj.msg = "implmentation for grand mode ".. implementation .." not found"
            njt.status = njt.HTTP_FORBIDDEN
            njt.say(cjson.encode(retObj))
            return njt.exit(njt.status)
        else 
            implementObj.check(apiObj)
        end 
    end
end

function accessControl.new(base_path)
    local self = {}
    setmetatable(self, {
        __index = ACCESSCTL
    })

    self.base_path = base_path
    return self
end

return accessControl
