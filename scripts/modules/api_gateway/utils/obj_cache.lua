local _M={}

local lrucache = require("resty.lrucache")
local apiGroupDao = require("api_gateway.dao.api_group")
local apiDao = require("api_gateway.dao.api")
local config = require("api_gateway.config.config")
local deployApp = require("api_gateway.service.deploy_app")

local apiCache, err = lrucache.new(400)  
if not apiCache then
    error("failed to create the cache: " .. (err or "unknown"))
end

function _M.getApiGroupById(id)
    local objKey="API_GROUP_ID_"..tostring(id)
    local object = apiCache:get(objKey)

    if object then
        return true, object
    else 
        local ok, apiGroupObj = apiGroupDao.getApiGroupById(id)
        if ok then 
            apiCache:set(objKey, apiGroupObj, tonumber(config.obj_cache_lifetime) or 120)
        end 
        return ok, apiGroupObj
    end
end

function _M.getApiGroupByBasePath(basePath)
    local objKey="API_GROUP_"..basePath
    local object = apiCache:get(objKey)

    if object then
        return true, object
    else 
        local ok, apiGroupObj = apiGroupDao.getApiGroupByBasePath(basePath)
        if ok then 
            apiCache:set(objKey, apiGroupObj, tonumber(config.obj_cache_lifetime) or 120)
        end 
        return ok, apiGroupObj
    end
end

function _M.getApisByGroupAndMethod(apiGroupId, method)
    local objKey="APIS_GROUP_METHOD_"..tostring(apiGroupId)..method
    local object = apiCache:get(objKey)

    if object then
        return true, object
    else 
        local criteria= string.format(" where group_id = %s and lower(method) = '%s'", apiGroupId, method)
        local ok, apis = apiDao.getApisByCriteria(criteria)
        if ok then 
            apiCache:set(objKey, apis, tonumber(config.obj_cache_lifetime) or 120)
        end 
        return ok, apis
    end
end

function _M.getApiGrantModes(apiId)
    local objKey="API_GRANT_"..apiId
    local object = apiCache:get(objKey)

    if object then
        return true, object
    else 
        local ok, grantModes = apiDao.getApiGrantModes(apiId)
        if ok then 
            apiCache:set(objKey, grantModes, tonumber(config.obj_cache_lifetime) or 120)
        end 
        return ok, grantModes
    end
end

function _M.getAppManifest(appName)
    local objKey="APP_MANIFEST_"..appName
    local object = apiCache:get(objKey)

    if object then
        return true, object
    else 
        local ok, obj = deployApp.read_manifest(appName)
        if ok then 
            apiCache:set(objKey, obj, tonumber(config.obj_cache_lifetime) or 120)
        else 
            njt.log(njt.DEBUG, "can't get manifest"..obj)
        end 
        return ok, obj
    end
end

function _M.clearApiCache()
    apiCache:flush_all()
end

return _M