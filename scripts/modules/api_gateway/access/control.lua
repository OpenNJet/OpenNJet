local accessControl = {}
-- class table
local ACCESSCTL = {}

local radixtree = require("resty.radixtree")
local objCache = require("api_gateway.utils.obj_cache")
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
    PARAM_USERNAME = -1, 
    ALWAYS = 0, 
    RBAC = 1, 
    COOKIE = 2
}

local GRANT_MODE_IMPLEMENT = {
    [-1] = "param_username", 
    [1] = "rbac",
    [2] = "cookie"
}

-- Convert OpenAPI {id} to :id
local function convert_openapi_path(path)
    return path:gsub("{(%w+)}", ":%1")
end

function ACCESSCTL:getApiId(apiGroupId)
   local ok, apis = objCache.getApisByGroupAndMethod(tostring(apiGroupId.id), string.lower(njt.req.get_method()))
   if not ok then 
       return false, nil
   end

   local routes={}
   for _, api in ipairs(apis) do
      local r = {}
      local path = convert_openapi_path(self.base_path..api.path)
      r.paths= {[1]= path}
      r.metadata = api
      table.insert(routes, r)
    end
  
    local rx = radixtree.new(routes)
    local request_url = njt.var.uri 
    if njt.var.uri == self.base_path  and not request_url:match("/$") then
        request_url = self.base_path .. "/"
    end
    local metadata = rx:match(request_url)
    if metadata then
        return true, metadata
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
    local ok, apiGroupObj = objCache.getApiGroupByBasePath(self.base_path)
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
    local ok, grantModes = objCache.getApiGrantModes(apiObj.id)
    if not ok or #grantModes == 0 then
        retObj.code = RETURN_CODE.API_GRANT_MODE_NOT_FOUND
        retObj.msg = "grant mode is not configured for api '" .. njt.var.uri .. "'"
        njt.status = njt.HTTP_FORBIDDEN
        njt.say(cjson.encode(retObj))
        return njt.exit(njt.status)
    end

    -- base on the grant_mode, create corresponding sevice to do validation, 
    -- right now only first grant_mode is checked
    if grantModes[1].grant_mode == GRANT_MODES.ALWAYS then
        return 
    end
    local implementation = GRANT_MODE_IMPLEMENT[grantModes[1].grant_mode] 
    if not implementation then
        retObj.code = RETURN_CODE.API_GRANT_MODE_NOT_FOUND
        retObj.msg = "grand mode ".. tostring(grantModes[1].grant_mode).." not implemented yet"
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
            implementObj.check(apiObj, grantModes[1])
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
