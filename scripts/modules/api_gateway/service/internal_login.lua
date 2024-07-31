local userDao = require("api_gateway.dao.user")
local util = require("api_gateway.utils.util")
local authDao = require("api_gateway.dao.auth")
local tokenLib=require("njt.token")

local _M = {}

local function get_user_with_username_password(login_data)
    -- if password is empty, return 
    if not login_data.password then
        return false, nil
    end

    local encryptedPassword = util.encryptPassword(login_data.password)
    return userDao.getUserByNameAndPassword(login_data.username, encryptedPassword)
end

local function get_user_with_email(login_data)
    -- if verification_code is empty, return 
    if not login_data.verification_code then
        return false, nil
    end

    -- validate verification_code
    -- local ok, retObj = authDao.getVerificationCode(login_data.verification_code)
    local rc, token=tokenLib.token_get("sms_login_token_"..login_data.email)
    njt.log(njt.ERR, "sms token is: ".. tostring(token))
    if rc ~= 0 or not token or token ~= login_data.verification_code then 
        return false, "verification code is not valid"
    end

    return userDao.getUserByEmail(login_data.email)
end

function _M.login(login_data)
    local userObj = nil
    local ok = false
    if  login_data.username  then
        ok, userObj = get_user_with_username_password(login_data)
    elseif login_data.email then
        ok, userObj = get_user_with_email(login_data)
    end

    if not ok then
        return false, userObj
    end

    return true, userObj.id
end

return _M
