local md5 = require("api_gateway.utils.md5")

local _M = {}

function _M.checkEmail(email)
    if not email or type(email) ~= "string" then
        return false
    end

    if (email:match("[A-Za-z0-9%.%%%+%-]+@[A-Za-z0-9%.%%%+%-]+%.%w%w%w?%w?")) then
        return true
    else
        return false
    end
end

function _M.checkMobile(mobile)
    if type(mobile) == "number" and #tostring(mobile) == 11 then
        return true
    end

    if type(mobile) == "string" and #mobile == 11 and tonumber(mobile) then
        return true
    end
    return false
end

function _M.encryptPassword(msg)
    return md5.sumhexa(msg)
end

function _M.isArray(t)
    if type(t) ~= "table" then
        return false
    end
    local i = 0
    for _ in pairs(t) do
        i = i + 1
        if t[i] == nil then
            return false
        end
    end
    return true
end

return _M
