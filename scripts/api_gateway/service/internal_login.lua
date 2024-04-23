local userDao = require("api_gateway.dao.user")
local util = require("api_gateway.utils.util")

local _M= {}

function _M.login(login_data)
    if not login_data.username or not login_data.password then
        return false, "username and password fields are mandatory"
    end

    local encryptedPassword = util.encryptPassword(login_data.password)

    local ok, userObj = userDao.getUserByNameAndPassword(login_data.username, encryptedPassword)
    if not ok then
        return false, "username or password is incorrect"
    end

    local ok, userRoleObj = userDao.getUserRoleRel(userObj.id)
    if not ok then
        return false, "can't get user role"
    end

    return true, userRoleObj.roles
end

return _M