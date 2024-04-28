local sqlite3db = require("api_gateway.dao.sqlite3db")

local _M = {}

function _M.getUserById(id)
    local userObj = {}
    local ok, db = sqlite3db.init()
    if not ok then
        return false, "can't open db"
    end

    local sql = "SELECT * FROM api_user WHERE id = ?"
    local stmt = db:prepare(sql)
    if not stmt then
        sqlite3db.finish()
        return false, "can't open api_user table"
    else
        stmt:bind_values(id)
        for row in stmt:nrows() do
            userObj.id = row.id
            userObj.name = row.name
            userObj.email = row.email or ""
            userObj.mobile = row.mobile or ""
        end
        stmt:finalize()
    end

    sqlite3db.finish()

    if not userObj.id then
        return false, "user is not existed"
    end
    return true, userObj
end

function _M.getUserByName(name)
    local userObj = {}
    local ok, db = sqlite3db.init()
    if not ok then
        return false, "can't open db"
    end

    local sql = "SELECT * FROM api_user WHERE name = ?"
    local stmt = db:prepare(sql)
    if not stmt then
        sqlite3db.finish()
        return false, "can't open api_user table"
    else
        stmt:bind_values(name)
        -- in db schema, name is UNIQUE, one record will be return 
        for row in stmt:nrows() do
            userObj.id = row.id
            userObj.name = row.name
            userObj.email = row.email or ""
            userObj.mobile = row.mobile or ""
        end
        stmt:finalize()
    end

    sqlite3db.finish()

    if not userObj.id then
        return false, "user is not existed"
    end
    return true, userObj
end

function _M.getUserByEmail(email)
    local userObj = {}
    local ok, db = sqlite3db.init()
    if not ok then
        return false, "can't open db"
    end

    local sql = "SELECT * FROM api_user WHERE email = ?"
    local stmt = db:prepare(sql)
    if not stmt then
        sqlite3db.finish()
        return false, "can't open api_user table"
    else
        stmt:bind_values(email)
        -- in db schema, name is UNIQUE, one record will be return 
        for row in stmt:nrows() do
            userObj.id = row.id
            userObj.name = row.name
            userObj.email = row.email or ""
            userObj.mobile = row.mobile or ""
        end
        stmt:finalize()
    end

    sqlite3db.finish()

    if not userObj.id then
        return false, "user is not existed"
    end
    return true, userObj
end

function _M.getUserByNameAndPassword(name, password)
    local userObj = {}
    local ok, db = sqlite3db.init()
    if not ok then
        return false, "can't open db"
    end

    local sql = "SELECT * FROM api_user WHERE name = ? and password = ?"
    local stmt = db:prepare(sql)
    if not stmt then
        sqlite3db.finish()
        return false, "can't open api_user table"
    else
        stmt:bind_values(name, password)
        -- in db schema, name is UNIQUE, one record will be return 
        for row in stmt:nrows() do
            userObj.id = row.id
            userObj.name = row.name
            userObj.email = row.email or ""
            userObj.mobile = row.mobile or ""
        end
        stmt:finalize()
    end

    sqlite3db.finish()

    if not userObj.id then
        return false, "can't get user"
    end
    return true, userObj
end


function _M.deleteUserById(id)
    local deleteOk = true
    local retObj = ""

    local ok, db = sqlite3db.init()
    if not ok then
        return false, "can't open db"
    end

    -- id has been valided in caller
    local sql = string.format("DELETE FROM api_user WHERE id = %d ; DELETE FROM api_user_group_rel WHERE user_id = %d", id, id)
    local result = db:exec(sql)
    if result ~= sqlite3db.OK then
        deleteOk = false
        retObj = db:errmsg()
    end

    sqlite3db.finish() 
    return deleteOk, retObj
end

function _M.createUser(userObj)
    local insertOk =false
    local retObj = {}
    local ok, db = sqlite3db.init()
    if not ok then
        return false, "can't open db"
    end

    local sql = "insert into api_user(name, password, email, mobile) values (?,?, ?, ?)"
    local stmt = db:prepare(sql)
    if not stmt then
        sqlite3db.finish()
        return false, "can't open api_user table"
    else
        stmt:bind_values(userObj.name, userObj.password, userObj.email, userObj.mobile)
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

function _M.updateUser(userObj)
    local updateOk =false
    local retMsg= ""
    local ok, db = sqlite3db.init()
    if not ok then
        return false, "can't open db"
    end

    local sql = "update api_user set "
    local setFields = {}
    local fields = {}

    for _, v in ipairs({"name", "password", "email", "mobile"}) do 
        if userObj[v] then
            table.insert(setFields, v .. " = ?")
            table.insert(fields, userObj[v])
        end
    end
    table.insert(fields, userObj.id)
    sql = sql .. table.concat(setFields, " , ") .. " where id = ?"

    local stmt = db:prepare(sql)
    if not stmt then
        sqlite3db.finish()
        return false, "can't open api_user table"
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

function _M.getUserRoleRel(id)
    local userRoleObj = {roles={}}
    local ok, db = sqlite3db.init()
    if not ok then
        return false, "can't open db"
    end

    local sql = "select augrr.role_id from api_user u, api_user_group_rel augr, api_user_group_role_rel augrr where u.id= ? and augr.user_id = u.id and augr.group_id=augrr.group_id"
    local stmt = db:prepare(sql)
    if not stmt then
        sqlite3db.finish()
        return false, "can't open db tables"
    else
        stmt:bind_values(id)
        for row in stmt:nrows() do
            table.insert(userRoleObj.roles, row.role_id)
        end
        stmt:finalize()
    end

    sqlite3db.finish()

    return true, userRoleObj
end

function _M.getUserGroupRel(id)
    local userGroupObj = {groups={}}
    local ok, db = sqlite3db.init()
    if not ok then
        return false, "can't open db"
    end

    local sql = "SELECT * FROM api_user_group_rel WHERE user_id = ?"
    local stmt = db:prepare(sql)
    if not stmt then
        sqlite3db.finish()
        return false, "can't open api_user_group_rel table"
    else
        stmt:bind_values(id)
        for row in stmt:nrows() do
            table.insert(userGroupObj.groups, row.group_id)
        end
        stmt:finalize()
    end

    sqlite3db.finish()

    return true, userGroupObj
end

function _M.updateUserGroupRel(relObj)
    local updateOk = false
    local retObj = ""
    local ok, db = sqlite3db.init()
    if not ok then
        return false, "can't open db"
    end

    local sqls = {}
    --userId/groupId  have been verified in caller, here just assume userId/groupId is always correct 
    table.insert(sqls,string.format("delete from api_user_group_rel where user_id = %d ;", relObj.id))
    for _,v in ipairs(relObj.groups) do
        table.insert(sqls, string.format("insert into api_user_group_rel(user_id, group_id) values(%d, %d);", relObj.id, v ))
    end

    local sql =table.concat(sqls, "\n");
    local result = db:exec(sql)
    if result ~= sqlite3db.OK then
        retObj = db:errmsg()
        updateOk = false
    else 
        updateOk = true
    end

    sqlite3db.finish()
    return updateOk, retObj
end

return _M
