local pairs = pairs
local type = type
local setmetatable = setmetatable
local tinsert = table.insert
local tconcat = table.concat
local utils = require("lor.lib.utils.utils")

local Response = {}

function Response:new()
    --njt.status = 200
    local instance = {
        http_status = nil,
        headers = {},
        locals = {},
        body = '--default body. you should not see this by default--',
        view = nil
    }

    setmetatable(instance, { __index = self })
    return instance
end

-- todo: optimize-compile before used
function Response:render(view_file, data)
    if not self.view then
        njt.log(njt.ERR, "`view` object is nil, maybe you disabled the view engine.")
        error("`view` object is nil, maybe you disabled the view engine.")
    else
        self:set_header('Content-Type', 'text/html; charset=UTF-8')
        data = data or {}
        data.locals = self.locals -- inject res.locals

        local body = self.view:render(view_file, data)
        self:_send(body)
    end
end


function Response:html(data)
    self:set_header('Content-Type', 'text/html; charset=UTF-8')
    self:_send(data)
end

function Response:json(data, empty_table_as_object)
    self:set_header('Content-Type', 'application/json; charset=utf-8')
    self:_send(utils.json_encode(data, empty_table_as_object))
end

function Response:redirect(url, code, query)
    if url and not code and not query then -- only one param
        njt.redirect(url)
    elseif url and code and not query then -- two param
        if type(code) == "number" then
            njt.redirect(url ,code)
        elseif type(code) == "table" then
            query = code
            local q = {}
            local is_q_exist = false
            if query and type(query) == "table" then
                for i,v in pairs(query) do
                    tinsert(q, i .. "=" .. v)
                    is_q_exist = true
                end
            end

            if is_q_exist then
                url = url .. "?" .. tconcat(q, "&")
            end

            njt.redirect(url)
        else
            njt.redirect(url)
        end
    else -- three param
        local q = {}
        local is_q_exist = false
        if query and type(query) == "table" then
           for i,v in pairs(query) do
               tinsert(q, i .. "=" .. v)
               is_q_exist = true
           end
        end

        if is_q_exist then
            url = url .. "?" .. tconcat(q, "&")
        end
        njt.redirect(url ,code)
    end
end

function Response:location(url, data)
    if data and type(data) == "table" then
        njt.req.set_uri_args(data)
        njt.req.set_uri(url, false)
    else
        njt.say(url)
        njt.req.set_uri(url, false)
    end
end

function Response:send(text)
    self:set_header('Content-Type', 'text/plain; charset=UTF-8')
    self:_send(text)
end

--~=============================================================

function Response:_send(content)
    njt.status =  self.http_status or 200
    njt.say(content)
end

function Response:get_body()
    return self.body
end

function Response:get_headers()
    return self.headers
end

function Response:get_header(key)
    return self.headers[key]
end

function Response:set_body(body)
    if body ~= nil then self.body = body end
end

function Response:status(status)
    njt.status = status
    self.http_status = status
    return self
end

function Response:set_header(key, value)
    njt.header[key] = value
end

return Response
