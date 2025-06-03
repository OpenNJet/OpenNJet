local sqlite3db = require("api_gateway.dao.sqlite3db")

local _M = {}

function _M.createApiGroup(apiGroupObj)
    local insertOk =false
    local retObj = {}
    local ok, db = sqlite3db.init()
    if not ok then
        return false, "can't open db"
    end

    local sql = "insert into api_group(name, base_path, desc, domain, user_id) values (?,?,?,?,?)"
    local stmt = db:prepare(sql)
    if not stmt then
        sqlite3db.finish()
        return false, "can't open api_group table"
    else
        stmt:bind_values(apiGroupObj.name, apiGroupObj.base_path, apiGroupObj.desc, apiGroupObj.domain, apiGroupObj.user_id)
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

function _M.getApiGroupById(id)
    local apiGroupObj = {}
    local ok, db = sqlite3db.init()
    if not ok then
        return false, "can't open db"
    end

    local sql = "SELECT * FROM api_group WHERE id = ?"
    local stmt = db:prepare(sql)
    if not stmt then
        sqlite3db.finish()
        return false, "can't open api_group table"
    else
        stmt:bind_values(id)
        for row in stmt:nrows() do
            apiGroupObj.id = row.id
            apiGroupObj.name = row.name
            apiGroupObj.base_path = row.base_path
            apiGroupObj.desc = row.desc or ""
            apiGroupObj.domain = row.domain or ""
            apiGroupObj.user_id = tonumber(row.user_id)
        end
        stmt:finalize()
    end

    sqlite3db.finish()

    if not apiGroupObj.id then
        return false, "api_group is not existed"
    end
    return true, apiGroupObj
end

function _M.getApiGroupByName(name)
    local apiGroupObj = {}
    local ok, db = sqlite3db.init()
    if not ok then
        return false, "can't open db"
    end

    local sql = "SELECT * FROM api_group WHERE name = ?"
    local stmt = db:prepare(sql)
    if not stmt then
        sqlite3db.finish()
        return false, "can't open api_group table"
    else
        stmt:bind_values(name)
        -- in db schema, name is UNIQUE, one record will be return 
        for row in stmt:nrows() do
            apiGroupObj.id = row.id
            apiGroupObj.name = row.name
            apiGroupObj.base_path = row.base_path
            apiGroupObj.desc = row.desc or ""
            apiGroupObj.domain = row.domain or ""
            apiGroupObj.user_id = tonumber(row.user_id)
        end
        stmt:finalize()
    end

    sqlite3db.finish()

    if not apiGroupObj.id then
        return false, "api_group is not existed"
    end
    return true, apiGroupObj
end

function _M.getApiGroupByBasePath(base_path)
    local apiGroupObj = {}
    local ok, db = sqlite3db.init()
    if not ok then
        return false, "can't open db"
    end

    local sql = "SELECT * FROM api_group WHERE base_path = ?"
    local stmt = db:prepare(sql)
    if not stmt then
        sqlite3db.finish()
        return false, "can't open api_group table"
    else
        stmt:bind_values(base_path)
        -- in db schema, name is UNIQUE, one record will be return 
        for row in stmt:nrows() do
            apiGroupObj.id = row.id
            apiGroupObj.name = row.name
            apiGroupObj.base_path = row.base_path
            apiGroupObj.desc = row.desc or ""
            apiGroupObj.domain = row.domain or ""
            apiGroupObj.user_id = tonumber(row.user_id)
        end
        stmt:finalize()
    end

    sqlite3db.finish()

    if not apiGroupObj.id then
        return false, "api_group is not existed"
    end
    return true, apiGroupObj
end

function _M.updateApiGroup(apiGroupObj)
    local updateOk =false
    local retMsg= ""
    local ok, db = sqlite3db.init()
    if not ok then
        return false, "can't open db"
    end

    local sql = "update api_group set "
    local setFields = {}
    local fields = {}

    for _, v in ipairs({"name", "base_path", "desc", "domain"}) do 
        if apiGroupObj[v] then
            table.insert(setFields, v .. " = ?")
            table.insert(fields, apiGroupObj[v])
        end
    end
    table.insert(fields, apiGroupObj.id)
    sql = sql .. table.concat(setFields, " , ") .. " where id = ?"

    local stmt = db:prepare(sql)
    if not stmt then
        sqlite3db.finish()
        return false, "can't open api_group table"
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

function _M.deleteApiGroupById(id)
    local deleteOk = true
    local retObj = ""
    local ok, db = sqlite3db.init()
    if not ok then
        return false, "can't open db"
    end

    -- id has been valided in caller
    local sql = string.format("DELETE FROM api_grant_rbac where exists (select 1 from api where api.group_id= %d and api.id = api_grant_rbac.api_id) ; DELETE FROM api_grant_mode where exists (select 1 from api where api.group_id= %d and api.id = api_grant_mode.api_id) ; DELETE FROM api WHERE group_id = %d; DELETE FROM api_group where id = %d", id, id, id, id)
    local result = db:exec(sql)
    if result ~= sqlite3db.OK then
        deleteOk = false
        retObj = db:errmsg()
    end

    sqlite3db.finish() 
    
    return deleteOk, retObj
end

function _M.getApisInGroupById(id)
    local apisObj = {}
    local ok, db = sqlite3db.init()
    if not ok then
        return false, "can't open db"
    end

    local sql = [[
        SELECT api.*, 
               GROUP_CONCAT(api_role.name) as roles
        FROM api
        JOIN api_group ON api_group.id = api.group_id
        LEFT JOIN api_grant_rbac ON api_grant_rbac.api_id = api.id
        LEFT JOIN api_role ON api_role.id = api_grant_rbac.role_id
        WHERE api_group.id = ?
        GROUP BY api.id;
    ]]
    local stmt = db:prepare(sql)
    if not stmt then
        sqlite3db.finish()
        return false, "can't open api table"
    else
        stmt:bind_values(id)
        for row in stmt:nrows() do
            local api = {}
            for k, v in pairs(row) do
                api[k] = v
            end
            api.desc = api.desc or ""
            api.roles = api.roles or "" -- Ensure roles is an empty string if no roles are found
            table.insert(apisObj, api)
        end
        stmt:finalize()
    end

    sqlite3db.finish()

    return true, apisObj
end

function _M.getAllApiGroups(page_size, page_num)
    -- Input validation
    if not page_size or not page_num or page_size < 1 or page_num < 1 then
        return false, "invalid page_size or page_num"
    end

    local api_groups = {}
    local total_count = 0
    local ok, db = sqlite3db.init()
    if not ok then
        return false, "can't open db"
    end

    -- Get total count
    local count_sql = "SELECT COUNT(*) as total FROM api_group"
    local count_stmt = db:prepare(count_sql)
    if not count_stmt then
        sqlite3db.finish()
        return false, "can't open api_group query"
    end
    for row in count_stmt:nrows() do
        total_count = row.total
    end
    count_stmt:finalize()

    -- Calculate offset
    local offset = (page_num - 1) * page_size

    -- Get paginated users with ORDER BY
    local sql = "SELECT * FROM api_group ORDER BY id ASC LIMIT ? OFFSET ?"
    local stmt = db:prepare(sql)
    if not stmt then
        sqlite3db.finish()
        return false, "can't open api_group table"
    else
        stmt:bind_values(page_size, offset)
        local column_names = stmt:get_names()

        for row in stmt:nrows() do
            local rowObj = {}
            for _, col_name in ipairs(column_names) do
                rowObj[col_name] = row[col_name] or ""  -- Use empty string as default for nil
            end
            table.insert(api_groups, rowObj)
        end
        stmt:finalize()
    end

    sqlite3db.finish()

    local result = {
        api_groups = api_groups,
        total = total_count,
        pageSize = page_size,
        pageNum = page_num,
        pages = math.ceil(total_count / page_size)
    }

    return true, result
end

return _M