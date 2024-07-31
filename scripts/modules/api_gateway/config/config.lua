local split=require("util.split")
local configDao=require("api_gateway.dao.sys_config")

local _M ={
}

local default_config = {
    token_lifetime = 1800, 
    verification_code_lifetime = 120, 
    smtp = {
        host = "127.0.0.1",
        port = 25,
        starttls = false
    },
    email_from = "api@test.com",
    ctrl_api_base = "http://127.0.0.1:8081/api/v1"
}

function _M.convert_value(value, v_type)
    if not value then
        return value
    end
    if string.lower(v_type) == "number" then
        return tonumber(value)
    end
    if string.lower(v_type) == "boolean" then
        return (string.lower(value) == "true")
    end
    if string.lower(v_type) == "password" then
        local ok, encrypt_lib=pcall(require, "ssh_remote_mod")
        if ok then 
            local rc, decrypted_passwd=encrypt_lib.decrypt_msg(value)
            if rc == 0 then
                return decrypted_passwd
            end
        end
    end
    return value
end

function _M.load_from_db()
    local ok, configs=configDao.getSysConfig()
    if ok and configs and #configs>0 then
        for _, config in ipairs(configs) do
            local confs, confLen=split.split_string(config.config_key, ".")
            -- 配置项至多只能两个层级，如 smtp.username
            if confLen == 1 then 
                _M[confs[1]] = _M.convert_value(config.config_value, config.config_type)
            elseif confLen== 2 then 
                _M[confs[1]] = default_config[confs[1]] or {}
                _M[confs[1]][confs[2]] = _M.convert_value(config.config_value, config.config_type)
 
            end
        end
    end
end

_M.load_from_db()
setmetatable(_M, {__index = default_config})

return _M 