local _M = {}

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

function _M.startsWith(str, start)
    return str:sub(1, #start) == start
 end

function _M.endswith(str, suffix)
    return str:sub(-suffix:len()) == suffix
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