local sqlite3db = require("api_gateway.dao.sqlite3db")

local _M = {}

function _M.getToken(token)
    local retObj = {}
    local ok, db = sqlite3db.init()
    if not ok then
        return false, "can't open db"
    end

    local sql = "select * from api_auth_token where token = ?"
    local stmt = db:prepare(sql)
    if not stmt then
        sqlite3db.finish()
        return false, "can't open api_auth_token table"
    else
        stmt:bind_values(token)
        for row in stmt:nrows() do
            for k, v in pairs(row) do
                retObj[k] =v
            end
        end
        stmt:finalize()
    end

    sqlite3db.finish()

    if not retObj.id then
        return false, "token is not existed"
    end
    return true, retObj
end

function _M.storeToken(token, expire, role_ids)
    local insertOk = false
    local retObj = {}
    local ok, db = sqlite3db.init()
    if not ok then
        return false, "can't open db"
    end

    db:exec("delete from api_auth_token where expire < strftime('%s','now')")
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

function _M.getVerificationCode(code)
    local retObj = {}
    local ok, db = sqlite3db.init()
    if not ok then
        return false, "can't open db"
    end

    local sql = "select * from api_verification_code where code = ?"
    local stmt = db:prepare(sql)
    if not stmt then
        sqlite3db.finish()
        return false, "can't open api_verification_code table"
    else
        stmt:bind_values(code)
        for row in stmt:nrows() do
            for k, v in pairs(row) do
                retObj[k] =v
            end
        end
        stmt:finalize()
    end

    sqlite3db.finish()

    if not retObj.id then
        return false, "verification_code is not existed"
    end
    return true, retObj
end

function _M.storeVerificationCode(account, code, expire)
    local insertOk = false
    local retObj = {}
    local ok, db = sqlite3db.init()
    if not ok then
        return false, "can't open db"
    end

    db:exec("delete from api_verification_code where expire < strftime('%s','now')")
    local sql = "insert into api_verification_code (account, code, expire) values (?,?, ?)"
    local stmt = db:prepare(sql)
    if not stmt then
        sqlite3db.finish()
        return false, "can't open api_verification_code table"
    else
        stmt:bind_values(account, code, expire)
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
