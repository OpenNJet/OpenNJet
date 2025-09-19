local sfind = string.find
local pairs = pairs
local type = type
local setmetatable = setmetatable
local utils = require("lor.lib.utils.utils")

local Request = {}

-- new request: init args/params/body etc from http request
function Request:new()
    local body = {} -- body params
    local headers = njt.req.get_headers()
    local method = njt.req.get_method()

    -- only attempt to read body for methods that typically have one
    local has_body = (method == "POST" or method == "PUT" or method == "PATCH" or method == "DELETE")

    if has_body then
        local header = headers['Content-Type']
        -- the post request have Content-Type header set
        if header then
            if sfind(header, "application/x-www-form-urlencoded", 1, true) then
                njt.req.read_body()
                local post_args = njt.req.get_post_args()
                if post_args and type(post_args) == "table" then
                    for k,v in pairs(post_args) do
                        body[k] = v
                    end
                end
            elseif sfind(header, "application/json", 1, true) then
                njt.req.read_body()
                local json_str = njt.req.get_body_data()
                body = utils.json_decode(json_str)
            -- form-data request
            elseif sfind(header, "multipart", 1, true) then
                -- upload request, should not invoke njt.req.read_body()
            -- parsed as raw by default
            else
                njt.req.read_body()
                body = njt.req.get_body_data()
            end
        -- the post request have no Content-Type header set will be parsed as x-www-form-urlencoded by default
        else
            njt.req.read_body()
            local post_args = njt.req.get_post_args()
            if post_args and type(post_args) == "table" then
                for k,v in pairs(post_args) do
                    body[k] = v
                end
            end
        end
    end

    local instance = {
        path = njt.var.uri, -- uri
        method = njt.req.get_method(),
        query = njt.req.get_uri_args(),
        params = {},
        body = body,
        body_raw = njt.req.get_body_data(),
        url = njt.var.request_uri,
        origin_uri = njt.var.request_uri,
        uri = njt.var.request_uri,
        headers = headers, -- request headers

        req_args = njt.var.args,
        found = false -- 404 or not
    }
    setmetatable(instance, { __index = self })
    return instance
end

function Request:is_found()
    return self.found
end

function Request:set_found(found)
    self.found = found
end

return Request
