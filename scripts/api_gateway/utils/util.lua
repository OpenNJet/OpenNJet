local _M = {}
local HMAC_KEY = "xItp/m24fxz49pnm1wy"

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
    return njt.encode_base64(njt.hmac_sha1(HMAC_KEY, msg))
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

function _M.fileExists(name)
    local f=io.open(name,"r")
    if f~=nil then io.close(f) return true else return false end
 end

local function read_from_file(file_name)
    local f = io.open(file_name, "r")
    if not f then 
      return nil
    end
    local string = f:read("*all")
    f:close()
    return string
end

function _M.getBodyData()
    njt.req.read_body()
    local req_body = njt.req.get_body_data()
    if not req_body then
       local body_file = njt.req.get_body_file()
       if body_file then
         req_body = read_from_file(body_file)
       end
    end
    return req_body
end

return _M
