local sqlite3db = require("api_gateway.dao.sqlite3db")

_M = {}

function _M.createGroup(groupObj)
    local insertOk = false
    local retObj = {}
    local ok, db = sqlite3db.init()
    if not ok then
        return false, "can't open db"
    end

    local sql = "insert into api_user_group(name, desc) values (?,?)"
    local stmt = db:prepare(sql)
    if not stmt then
        sqlite3db.finish()
        return false, "can't open api_user_group table"
    else
        stmt:bind_values(groupObj.name, groupObj.desc)
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

function _M.getGroupById(id)
    local groupObj = {}
    local ok, db = sqlite3db.init()
    if not ok then
        return false, "can't open db"
    end

    local sql = "SELECT * FROM api_user_group WHERE id = ?"
    local stmt = db:prepare(sql)
    if not stmt then
        sqlite3db.finish()
        return false, "can't open api_user_group table"
    else
        stmt:bind_values(id)
        for row in stmt:nrows() do
            groupObj.id = row.id
            groupObj.name = row.name
            groupObj.desc = row.desc or ""
        end
        stmt:finalize()
    end

    sqlite3db.finish()

    if not groupObj.id then
        return false, "group is not existed"
    end
    return true, groupObj
end

function _M.getGroupByName(name)
    local groupObj = {}
    local ok, db = sqlite3db.init()
    if not ok then
        return false, "can't open db"
    end

    local sql = "SELECT * FROM api_user_group WHERE name = ?"
    local stmt = db:prepare(sql)
    if not stmt then
        sqlite3db.finish()
        return false, "can't open api_user_group table"
    else
        stmt:bind_values(name)
        -- in db schema, name is UNIQUE, one record will be return 
        for row in stmt:nrows() do
            groupObj.id = row.id
            groupObj.name = row.name
            groupObj.desc = row.desc or ""
        end
        stmt:finalize()
    end

    sqlite3db.finish()

    if not groupObj.id then
        return false, "group is not existed"
    end
    return true, groupObj
end

function _M.updateGroup(groupObj)
    local updateOk = false
    local retMsg = ""
    local ok, db = sqlite3db.init()
    if not ok then
        return false, "can't open db"
    end

    local sql = "update api_user_group set "
    local setFields = {}
    local fields = {}

    for _, v in ipairs({"name", "desc"}) do
        if groupObj[v] then
            table.insert(setFields, v .. " = ?")
            table.insert(fields, groupObj[v])
        end
    end
    table.insert(fields, groupObj.id)
    sql = sql .. table.concat(setFields, " , ") .. " where id = ?"

    local stmt = db:prepare(sql)
    njt.log(njt.ERR, sql)
    if not stmt then
        sqlite3db.finish()
        return false, "can't open api_user_group table"
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

function _M.deleteGroupById(id)
    local deleteOk = true
    local retObj = ""

    local ok, db = sqlite3db.init()
    if not ok then
        return false, "can't open db"
    end
    -- id has been valided in caller
    local sql = string.format(
        "DELETE FROM api_user_group WHERE id = %d ; DELETE FROM api_user_group_role_rel WHERE group_id = %d", id, id)
    local result = db:exec(sql)
    if result ~= sqlite3db.OK then
        deleteOk = false
        retObj = db:errmsg()
    end

    sqlite3db.finish()
    return deleteOk, retObj
end

function _M.getUserGroupRoleRel(id)
    local userGroupRoleObj = {roles={}}
    local ok, db = sqlite3db.init()
    if not ok then
        return false, "can't open db"
    end

    local sql = "SELECT * FROM api_user_group_role_rel WHERE group_id = ?"
    local stmt = db:prepare(sql)
    if not stmt then
        sqlite3db.finish()
        return false, "can't open api_user_group_role_rel table"
    else
        stmt:bind_values(id)
        for row in stmt:nrows() do
            table.insert(userGroupRoleObj.roles, row.role_id)
        end
        stmt:finalize()
    end

    sqlite3db.finish()

    return true, userGroupRoleObj
end

function _M.updateUserGroupRoleRel(relObj)
    local updateOk = false
    local retObj = ""
    local ok, db = sqlite3db.init()
    if not ok then
        return false, "can't open db"
    end

    local sqls = {}
    --groupId/roleId  have been verified in caller, here just assume groupId/roleId is always correct 
    table.insert(sqls,string.format("delete from api_user_group_role_rel where group_id = %d ;", relObj.id))
    for _,v in ipairs(relObj.roles) do
        table.insert(sqls, string.format("insert into api_user_group_role_rel(group_id, role_id) values(%d, %d);", relObj.id, v ))
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
