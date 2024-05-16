local ffi = require("ffi")

ffi.cdef[[
    typedef intptr_t  njt_int_t;
    njt_int_t njt_openapi_parse_json(njt_str_t *json_str, njt_str_t *db_name, njt_int_t group_id);
]]

local _M={}

function _M.oas3_json_import(oas3_json, sqlite3_db, api_group_id)
    if type(oas3_json) ~= "string" then
        return -1, "oas3_json should be a valid string"
    end
    if type(sqlite3_db) ~= "string" then
        return -1, "sqlite3_db should be a valid string"
    end
    if type(api_group_id) ~= "number" then
        return -1, "api_group_id should be a valid number"
    end

    local oas3_json_t = ffi.new("njt_str_t[1]")
    local sqlite3_db_t = ffi.new("njt_str_t[1]")
    local json_str = oas3_json_t[0]
    local db_name = sqlite3_db_t[0]
    json_str.data=oas3_json
    json_str.len=#oas3_json
    db_name.data=sqlite3_db
    db_name.len=#sqlite3_db

    local rc=ffi.C.njt_openapi_parse_json(oas3_json_t, sqlite3_db_t, api_group_id)
    if rc == 0 then 
        return 0, "success"
    else 
        return -1, "error occuried, check if json is a valid oas3 document"
    end
end

return _M
