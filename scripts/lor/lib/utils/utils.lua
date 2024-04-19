local type = type
local pairs = pairs
local setmetatable = setmetatable
local mrandom = math.random
local sreverse = string.reverse
local sfind = string.find
local sgsub = string.gsub
local smatch = string.match
local table_insert = table.insert
local json = require("cjson")

local _M = {}

function _M.clone(o)
    local lookup_table = {}
    local function _copy(object)
        if type(object) ~= "table" then
            return object
        elseif lookup_table[object] then
            return lookup_table[object]
        end
        local new_object = {}
        lookup_table[object] = new_object
        for key, value in pairs(object) do
            new_object[_copy(key)] = _copy(value)
        end
        return setmetatable(new_object, getmetatable(object))
    end
    return _copy(o)
end

function _M.clear_slash(s)
    local r, _ = sgsub(s, "(/+)", "/")
    return r
end

function _M.is_table_empty(t)
    if t == nil or _G.next(t) == nil then
        return true
    else
        return false
    end
end

function _M.table_is_array(t)
    if type(t) ~= "table" then return false end
    local i = 0
    for _ in pairs(t) do
        i = i + 1
        if t[i] == nil then return false end
    end
    return true
end

function _M.mixin(a, b)
    if a and b then
        for k, _ in pairs(b) do
            a[k] = b[k]
        end
    end
    return a
end

function _M.random()
    return mrandom(0, 10000)
end

function _M.json_encode(data, empty_table_as_object)
    local json_value
    if json.encode_empty_table_as_object then
        -- empty table encoded as array default
        json.encode_empty_table_as_object(empty_table_as_object or false) 
    end
    if require("ffi").os ~= "Windows" then
        json.encode_sparse_array(true)
    end
    pcall(function(d) json_value = json.encode(d) end, data)
    return json_value
end

function _M.json_decode(str)
    local ok, data = pcall(json.decode, str)
    if ok then
        return data
    end
end

function _M.start_with(str, substr)
    if str == nil or substr == nil then
        return false
    end
    if sfind(str, substr) ~= 1 then
        return false
    else
        return true
    end
end

function _M.end_with(str, substr)
    if str == nil or substr == nil then
        return false
    end
    local str_reverse = sreverse(str)
    local substr_reverse = sreverse(substr)
    if sfind(str_reverse, substr_reverse) ~= 1 then
        return false
    else
        return true
    end
end

function _M.is_match(uri, pattern)
    if not pattern then
        return false
    end

    local ok = smatch(uri, pattern)
    if ok then return true else return false end
end

function _M.trim_prefix_slash(s)
    local str, _ = sgsub(s, "^(//*)", "")
    return str
end

function _M.trim_suffix_slash(s)
    local str, _ = sgsub(s, "(//*)$", "")
    return str
end

function _M.trim_path_spaces(path)
    if not path or path == "" then return path end
    return sgsub(path, "( *)", "")
end

function _M.slim_path(path)
    if not path or path == "" then return path end
    return sgsub(path, "(//*)", "/")
end

function _M.split(str, delimiter)
    if not str or str == "" then return {} end
    if not delimiter or delimiter == "" then return { str } end

    local result = {}
    for match in (str .. delimiter):gmatch("(.-)" .. delimiter) do
        table_insert(result, match)
    end
    return result
end

return _M
