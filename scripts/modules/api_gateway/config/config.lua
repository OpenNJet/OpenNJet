local split=require("util.split")
local configDao=require("api_gateway.dao.sys_config")
local tokenLib = require("njt.token")
local configConst = require("api_gateway.config.const")

local _M ={
}

local default_config = {
    uploaded_file_path = "data/file_upload/",
    check_db_change_flag_in_session = false, 
    changes_notification_lifetime = 120, -- for db config changes notification ttl to other nodes
    obj_cache_lifetime = 120,  -- for object ttl in lrucache
    token_lifetime = 1800,  -- for login token ttl
    verification_code_lifetime = 120,  -- for sms/email code ttl
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
    _M.__config_loaded_time = njt.now()
end

_M.load_from_db()
setmetatable(_M, {__index = default_config})

--create proxy table
local t={}
local mt = {
    __index = function (t,k)
      if _M.check_db_change_flag_in_session then
        -- if config has been changed by master node, it will set CONFIG_CHANGES_SESSION_KEY into session with modified time
        local rc, tv_str=tokenLib.token_get(configConst.CONFIG_CHANGES_SESSION_KEY)
        if rc == 0 and tv_str and tv_str ~= "" and tonumber(_M.__config_loaded_time) and tonumber(tv_str) and tonumber(tv_str) > tonumber(_M.__config_loaded_time) then
            _M.load_from_db()
        end  
      end
      -- periodic reload config data in case database has been changed manually by sql
      if tonumber(_M.__config_loaded_time) and njt.now() - tonumber(_M.__config_loaded_time)  > 300 then
        _M.load_from_db()
      end
      return _M[k]   -- access the original table
    end,
  
    __newindex = function (t,k,v)
      _M[k] = v   -- update original table
    end
  }
  setmetatable(t, mt)
  return t