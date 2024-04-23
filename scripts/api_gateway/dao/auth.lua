local sqlite3db = require("api_gateway.dao.sqlite3db")

local _M = {}

function _M.storeToken(token, expire, role_ids)
    local insertOk =false
    local retObj = {}
    local ok, db = sqlite3db.init()
    if not ok then
        return false, "can't open db"
    end

    local sql = "insert into api_auth_token (token, expire, role_ids) values (?,?, ?)"
    local stmt = db:prepare(sql)
    if not stmt then
        sqlite3db.finish()
        return false, "can't open api_auth_token table"
    else
        stmt:bind_values(token, expire, role_ids)
        local result = stmt:step()

        if result == sqlite3db.DONE then
            retObj.id = stmt:last_insert_rowid()
            insertOk = true
        else
            retObj = db:errmsg()
            insertOk = false
        end
    end
    stmt:finalize()
    sqlite3db.finish()
    return insertOk, retObj
end

return _M
