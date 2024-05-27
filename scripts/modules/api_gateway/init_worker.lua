if require("njt.process").type() ~= "privileged agent" then
    balancer.init_worker()
else 
    local configuration_data = njt.shared.configuration_data
    local kv = require("njt.kv")
    local rc, backends = kv.db_kv_get("__LUA_UPSTREAM_BACKENDS")
    if rc == 0  then
        local now = njt.now()
        configuration_data:set("backends", backends)
        configuration_data:set("hc_backends", backends)
        configuration_data:set("raw_backends_last_synced_at", now)
        configuration_data:set("raw_hc_backends_last_synced_at", now)
    end
    health_check.init_worker(configuration, njt.shared.configuration_data)  
end