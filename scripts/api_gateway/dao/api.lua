local sqlite3db = require("api_gateway.dao.sqlite3db")

local _M = {}

function _M.deleteApisByGroupId(id)
    local deleteOk = true
    local retObj = ""
    local ok, db = sqlite3db.init()
    if not ok then
        return false, "can't open db"
    end

    -- id has been valided in caller
    local sql = string.format("DELETE FROM api_grant_mode where exists (select 1 from api where api.group_id= %d and api.id = api_grant_mode.api_id) ; DELETE FROM api WHERE group_id = %d; ", id, id)
    local result = db:exec(sql)
    if result ~= sqlite3db.OK then
        deleteOk = false
        retObj = db:errmsg()
    end

    sqlite3db.finish() 
    
    return deleteOk, retObj
end


return _M