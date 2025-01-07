local sqlite3db = require("api_gateway.dao.sqlite3db")

local _M = {}

function _M.getSysConfig()
    local retArray = {}
    local ok, db = sqlite3db.init()
    if not ok then
        return false, "can't open db"
    end

    local sql = "SELECT * FROM sys_config"
    local stmt = db:prepare(sql)
    if not stmt then
        sqlite3db.finish()
        return false, "can't open sys_config table"
    else
        for row in stmt:nrows() do
            local retObj = {}
            retObj.id = row.id
            retObj.config_key = row.config_key
            retObj.config_value = row.config_value
            retObj.config_type = row.config_type
            table.insert(retArray, retObj)
        end
        stmt:finalize()
    end

    sqlite3db.finish()

    return true, retArray
end

function _M.getSysConfigByKey(config_key)
    local retArray = {}
    local ok, db = sqlite3db.init()
    if not ok then
        return false, "can't open db"
    end

    local sql = "SELECT * FROM sys_config where config_key = ?"
    local stmt = db:prepare(sql)
    if not stmt then
        sqlite3db.finish()
        return false, "can't open sys_config table"
    else
        stmt:bind_values(config_key)
        for row in stmt:nrows() do
            local retObj = {}
            retObj.config_key = row.config_key
            retObj.config_value = row.config_value
            retObj.config_type = row.config_type
            table.insert(retArray, retObj)
        end
        stmt:finalize()
    end

    sqlite3db.finish()

    return true, retArray
end

function _M.updateSysConfig(confs)
    local updateOk = false
    local retObj = ""
    local ok, db = sqlite3db.init()
    if not ok then
        return false, "can't open db"
    end

    local sqls = {}
    for _, conf in ipairs(confs) do
        table.insert(sqls,string.format("delete from sys_config where config_key = '%s' ;", conf.config_key))
  
        table.insert(sqls, string.format("insert into sys_config(config_key, config_value, config_type) values('%s', '%s', '%s');", conf.config_key, conf.config_value, conf.config_type))
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
