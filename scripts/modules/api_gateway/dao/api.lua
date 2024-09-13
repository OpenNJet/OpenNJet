local sqlite3db = require("api_gateway.dao.sqlite3db")

local _M = {}

function _M.getApiById(id)
    local apiObj = {}
    local ok, db = sqlite3db.init()
    if not ok then
        return false, "can't open db"
    end

    local sql = "SELECT * FROM api WHERE id = ?"
    local stmt = db:prepare(sql)
    if not stmt then
        sqlite3db.finish()
        return false, "can't open api table"
    else
        stmt:bind_values(id)
        for row in stmt:nrows() do
            for k, v in pairs(row) do
               apiObj[k] = v
            end
            apiObj.desc = apiObj.desc or ""
        end
        stmt:finalize()
    end

    sqlite3db.finish()

    if not apiObj.id then
        return false, "api is not existed"
    end
    return true, apiObj
end

-- use with caution, invoker must ensure criteria is valid 
function _M.getApisByCriteria(criteria)
    local apisObj = {}
    local ok, db = sqlite3db.init()
    if not ok then
        return false, "can't open db"
    end

    local sql = "SELECT * FROM api " .. criteria

    for row in  db:nrows(sql) do
        local api={}
        for k,v in pairs(row) do
           api[k]=v
        end
        table.insert(apisObj, api)
    end 

    sqlite3db.finish()

    if #apisObj ==0 then
        return false, "not api found"
    end

    return true, apisObj
end

function _M.getApiRoleRel(id)
    local apiRoleObj = {roles={}}
    local ok, db = sqlite3db.init()
    if not ok then
        return false, "can't open db"
    end

    local sql = "SELECT * FROM api_grant_rbac WHERE api_id = ?"
    local stmt = db:prepare(sql)
    if not stmt then
        sqlite3db.finish()
        return false, "can't open api_grant_rbac table"
    else
        stmt:bind_values(id)
        for row in stmt:nrows() do
            table.insert(apiRoleObj.roles, row.role_id)
        end
        stmt:finalize()
    end

    sqlite3db.finish()

    return true, apiRoleObj
end

function _M.getApiGrantModes(apiId)
    local grantModes = {}
    local ok, db = sqlite3db.init()
    if not ok then
        return false, "can't open db"
    end

    local sql = "select * from api_grant_mode where api_id=? order by grant_mode"
    local stmt = db:prepare(sql)
    if not stmt then
        sqlite3db.finish()
        return false, "can't open api table"
    else
        stmt:bind_values(apiId)
        for row in stmt:nrows() do
            table.insert(grantModes, row)
        end
       
        stmt:finalize()
    end

    sqlite3db.finish()

    if #grantModes == 0  then
        return false, "api grant mode is not configured"
    end
    return true, grantModes
end

function _M.deleteApisByGroupId(id)
    local deleteOk = true
    local retObj = ""
    local ok, db = sqlite3db.init()
    if not ok then
        return false, "can't open db"
    end

    -- id has been valided in caller
    local sql = string.format("DELETE FROM api_grant_rbac where exists (select 1 from api where api.group_id= %d and api.id = api_grant_rbac.api_id) ; DELETE FROM api_grant_mode where exists (select 1 from api where api.group_id= %d and api.id = api_grant_mode.api_id) ; DELETE FROM api WHERE group_id = %d; ", id, id, id)
    local result = db:exec(sql)
    if result ~= sqlite3db.OK then
        deleteOk = false
        retObj = db:errmsg()
    end

    sqlite3db.finish() 
    
    return deleteOk, retObj
end


return _M