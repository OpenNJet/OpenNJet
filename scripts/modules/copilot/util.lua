local _M ={}

local kv=require("njt.kv")

function _M.restartCopilotByLabel(label)
    local rc, pid = kv.db_kv_get("kv_http___COPILOT_PID_"..label)
    if rc == 0 then
        pid = tonumber(pid)
        if pid ~=nil then
            os.execute("kill " .. pid)
            return true, "success"
        else 
            return false, "pid is not valid in kvstore"
        end
    else 
        return false, "can't get copilot pid"
    end
end

return _M