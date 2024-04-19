local sqlite3db = require("api_gateway.dao.sqlite3db")

_M = {}

function _M.createRole(roleObj)
    local insertOk =false
    local retObj = {}
    local ok, db = sqlite3db.init()
    if not ok then
        return false, "can't open db"
    end

    local sql = "insert into api_role(name, desc) values (?,?)"
    local stmt = db:prepare(sql)
    if not stmt then
        sqlite3db.finish()
        return false, "can't open api_role table"
    else
        stmt:bind_values(roleObj.name, roleObj.desc)
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

function _M.getRoleById(id)
    local roleObj = {}
    local ok, db = sqlite3db.init()
    if not ok then
        return false, "can't open db"
    end

    local sql = "SELECT * FROM api_role WHERE id = ?"
    local stmt = db:prepare(sql)
    if not stmt then
        sqlite3db.finish()
        return false, "can't open api_role table"
    else
        stmt:bind_values(id)
        for row in stmt:nrows() do
            roleObj.id = row.id
            roleObj.name = row.name
            roleObj.desc = row.desc or ""
        end
        stmt:finalize()
    end

    sqlite3db.finish()

    if not roleObj.id then
        return false, "role is not existed"
    end
    return true, roleObj
end

function _M.getRoleByName(name)
    local roleObj = {}
    local ok, db = sqlite3db.init()
    if not ok then
        return false, "can't open db"
    end

    local sql = "SELECT * FROM api_role WHERE name = ?"
    local stmt = db:prepare(sql)
    if not stmt then
        sqlite3db.finish()
        return false, "can't open api_role table"
    else
        stmt:bind_values(name)
        -- in db schema, name is UNIQUE, one record will be return 
        for row in stmt:nrows() do
            roleObj.id = row.id
            roleObj.name = row.name
            roleObj.desc = row.desc or ""
        end
        stmt:finalize()
    end

    sqlite3db.finish()

    if not roleObj.id then
        return false, "role is not existed"
    end
    return true, roleObj
end

function _M.updateRole(roleObj)
    local updateOk =false
    local retMsg= ""
    local ok, db = sqlite3db.init()
    if not ok then
        return false, "can't open db"
    end

    local sql = "update api_role set "
    local setFields = {}
    local fields = {}

    for _, v in ipairs({"name", "desc"}) do 
        if roleObj[v] then
            table.insert(setFields, v .. " = ?")
            table.insert(fields, roleObj[v])
        end
    end
    table.insert(fields, roleObj.id)
    sql = sql .. table.concat(setFields, " , ") .. " where id = ?"

    local stmt = db:prepare(sql)
    njt.log(njt.ERR, sql)
    if not stmt then
        sqlite3db.finish()
        return false, "can't open api_role table"
    else
        stmt:bind_values(unpack(fields))

        local result = stmt:step()

        if result == sqlite3db.DONE then
            updateOk = true
        else
            retObj = db:errmsg()
            updateOk = false
        end
    end
    stmt:finalize()
    sqlite3db.finish()
    return updateOk, retObj
end

function _M.deleteRoleById(id)
    local ok, db = sqlite3db.init()
    if not ok then
        return false, "can't open db"
    end

    local sql = "DELETE FROM api_role WHERE id = ?"
    local stmt = db:prepare(sql)
    if not stmt then
        sqlite3db.finish()
        return false, "can't open api_role table"
    else
        stmt:bind_values(id)
        local result = stmt:step()
        if result == sqlite3db.DONE then
            updateOk = true
        else
            retObj = db:errmsg()
            updateOk = false
        end     

    end
    stmt:finalize()
    sqlite3db.finish()
    
    return true, ""
end

return _M