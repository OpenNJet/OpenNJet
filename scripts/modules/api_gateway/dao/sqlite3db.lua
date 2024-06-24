local lsqlite3=require("lsqlite3complete")
local config=require("api_gateway.config.config")

local _M = {}
setmetatable(_M, { __index = lsqlite3 })

-- in sqlite3, now it open and close db file everytime, should find a better way to access db and improve performance
function _M.init()
    local db= lsqlite3.open(config.db_file) 
    if not db:isopen() then
        njt.log(njt.ERR, "open api_gateway.db failed")
        return false
    end
    _M.db=db
    return true, db
end

function _M.finish()
    _M.db:close()
end



return _M