local sqlite3db = require("api_gateway.dao.sqlite3db")

local _M = {}

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
    local deleteOk = true
    local retObj = ""
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
            deleteOk = true
        else
            retObj = db:errmsg()
            deleteOk = false
        end     

    end
    stmt:finalize()
    sqlite3db.finish()
    
    return deleteOk, retObj
end

function _M.getRoleApiRel(id)
    local roleApiObj = {apis={}}
    local ok, db = sqlite3db.init()
    if not ok then
        return false, "can't open db"
    end

    local sql = "SELECT * FROM api_grant_rbac WHERE role_id = ?"
    local stmt = db:prepare(sql)
    if not stmt then
        sqlite3db.finish()
        return false, "can't open api_grant_rbac table"
    else
        stmt:bind_values(id)
        for row in stmt:nrows() do
            table.insert(roleApiObj.apis, row.api_id)
        end
        stmt:finalize()
    end

    sqlite3db.finish()

    return true, roleApiObj
end

function _M.updateRoleApiRel(relObj)
    local updateOk = false
    local retObj = ""
    local ok, db = sqlite3db.init()
    if not ok then
        return false, "can't open db"
    end

    local sqls = {}
    --roleId  have been verified in caller, here just assume roleId is always correct 
    table.insert(sqls,string.format("delete from api_grant_rbac where role_id = %d ;", relObj.id))
    for _,v in ipairs(relObj.apis) do
        table.insert(sqls, string.format("insert into api_grant_rbac(role_id, api_id) values(%d, %d);", relObj.id, v ))
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

function _M.getAllRoles(page_size, page_num)
    -- Input validation
    if not page_size or not page_num or page_size < 1 or page_num < 1 then
        return false, "invalid page_size or page_num"
    end

    local allObjs = {}
    local total_count = 0
    local ok, db = sqlite3db.init()
    if not ok then
        return false, "can't open db"
    end

    -- Get total count
    local count_sql = "SELECT COUNT(*) as total FROM api_role"
    local count_stmt = db:prepare(count_sql)
    if not count_stmt then
        sqlite3db.finish()
        return false, "can't open count query"
    end
    for row in count_stmt:nrows() do
        total_count = row.total
    end
    count_stmt:finalize()

    -- Calculate offset
    local offset = (page_num - 1) * page_size

    -- Get paginated groups with ORDER BY
    local sql = "SELECT * FROM api_role ORDER BY id ASC LIMIT ? OFFSET ?"
    local stmt = db:prepare(sql)
    if not stmt then
        sqlite3db.finish()
        return false, "can't open api_role table"
    else
        stmt:bind_values(page_size, offset)
        local column_names = stmt:get_names()

        for row in stmt:nrows() do
            local rowObj = {}
            for _, col_name in ipairs(column_names) do
                rowObj[col_name] = row[col_name] or ""  -- Use empty string as default for nil
            end
            table.insert(allObjs, rowObj)
        end
        stmt:finalize()
    end

    sqlite3db.finish()

    local result = {
        roles = allObjs,
        total = total_count,
        pageSize = page_size,
        pageNum = page_num,
        pages = math.ceil(total_count / page_size)
    }

    return true, result
end

return _M