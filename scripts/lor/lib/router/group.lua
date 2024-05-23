local setmetatable = setmetatable
local pairs = pairs
local type = type
local error = error
local next = next
local string_format = string.format
local string_lower = string.lower
local table_insert = table.insert
local unpack = table.unpack or unpack

local supported_http_methods = require("lor.lib.methods")
local debug = require("lor.lib.debug")
local utils = require("lor.lib.utils.utils")
local random = utils.random
local clone = utils.clone
local handler_error_tip = "handler must be `function` that matches `function(req, res, next) ... end`"

local Group = {}

function Group:new()
    local group = {}

    group.id = random()
    group.name =  "group-" .. group.id
    group.is_group = true
    group.apis = {}
    self:build_method()

    setmetatable(group, {
        __index = self,
        __call = self._call,
        __tostring = function(s)
            return s.name
        end
    })

    return group
end

--- a magick for usage like `lor:Router()`
-- generate a new group for different routes group
function Group:_call()
    local cloned = clone(self)
    cloned.id = random()
    cloned.name = cloned.name .. ":clone-" .. cloned.id
    return cloned
end

function Group:get_apis()
    return self.apis
end

function Group:set_api(path, method, ...)
    if not path or not method then
        return error("`path` & `method` should not be nil.")
    end

    local handlers = {...}
    if not next(handlers) then
        return error("handler should not be nil or empty")
    end

    if type(path) ~= "string" or type(method) ~= "string" or type(handlers) ~= "table" then
        return error("params type error.")
    end

    local extended_handlers = {}
    for _, h in ipairs(handlers) do
        if type(h) == "function" then
            table_insert(extended_handlers, h)
        elseif type(h) == "table" then
            for _, hh in ipairs(h) do
                if type(hh) == "function" then
                    table_insert(extended_handlers, hh)
                else
                    error(handler_error_tip)
                end
            end
        else
            error(handler_error_tip)
        end
    end

    method = string_lower(method)
    if not supported_http_methods[method] then
        return error(string_format("[%s] method is not supported yet.", method))
    end

    self.apis[path] = self.apis[path] or {}
    self.apis[path][method] = extended_handlers
end

function Group:build_method()
    for m, _ in pairs(supported_http_methods) do
        m = string_lower(m)

        -- 1. group_router:get(func1)
        -- 2. group_router:get(func1, func2)
        -- 3. group_router:get({func1, func2})
        -- 4. group_router:get(path, func1)
        -- 5. group_router:get(path, func1, func2)
        -- 6. group_router:get(path, {func1, func2})
        Group[m] = function(myself, ...)
            local params = {...}
            if not next(params) then return error("params should not be nil or empty") end

            -- case 1 or 3
            if #params == 1 then
                if type(params[1]) ~= "function" and type(params[1]) ~= "table" then
                    return error("it must be an function if there's only one param")
                end

                if type(params[1]) == "table" and #(params[1]) == 0 then
                    return error("params should not be nil or empty")
                end

                return Group.set_api(myself, "", m, ...)
            end

            -- case 2,4,5,6
            if #params > 1 then
                if type(params[1]) == "string" then -- case 4,5,6
                    return Group.set_api(myself, params[1], m, unpack(params, 2))
                else -- case 2
                    return Group.set_api(myself, "", m, ...)
                end
            end

            error("error params for group route define")
        end
    end
end

function Group:clone()
    local cloned = clone(self)
    cloned.id = random()
    cloned.name = cloned.name .. ":clone-" .. cloned.id
    return cloned
end

return Group
