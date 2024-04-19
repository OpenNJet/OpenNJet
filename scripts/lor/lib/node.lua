local setmetatable = setmetatable
local type = type
local next = next
local ipairs = ipairs
local table_insert = table.insert
local string_lower = string.lower
local string_format = string.format

local utils = require("lor.lib.utils.utils")
local supported_http_methods = require("lor.lib.methods")
local ActionHolder = require("lor.lib.holder").ActionHolder
local handler_error_tip = "handler must be `function` that matches `function(req, res, next) ... end`"
local middlware_error_tip = "middlware must be `function` that matches `function(req, res, next) ... end`"
local error_middlware_error_tip = "error middlware must be `function` that matches `function(err, req, res, next) ... end`"
local node_count = 0

local function gen_node_id()
    local prefix = "node-"
    local worker_part = "dw"
    if njt and njt.worker and njt.worker.id() then
        worker_part = njt.worker.id()
    end
    node_count = node_count + 1 -- simply count for lua vm level
    local unique_part = node_count
    local random_part = utils.random()
    local node_id = prefix .. worker_part  .. "-" .. unique_part .. "-" .. random_part
    return node_id
end

local function check_method(method)
    if not method then return false end

    method = string_lower(method)
    if not supported_http_methods[method] then
        return false
    end

    return true
end

local Node = {}

function Node:new(root)
    local is_root = false
    if root == true then
        is_root = true
    end

    local instance = {
        id = gen_node_id(),
        is_root = is_root,
        name = "",
        allow = "",
        pattern = "",
        endpoint = false,
        parent = nil,
        colon_parent = nil,
        children  = {},
        colon_child= nil,
        handlers = {},
        middlewares = {},
        error_middlewares = {},
        regex = nil
    }
    setmetatable(instance, {
        __index = self,
        __tostring = function(s)
            local ok, result = pcall(function()
                return string_format("name: %s", s.id)
            end)
            if ok then
                return result
            else
                return "node.tostring() error"
            end
        end
    })
    return instance
end

function Node:find_child(key)
    --print("find_child: ", self.id, self.name, self.children)
    for _, c in ipairs(self.children) do
        if key == c.key then
            return c.val
        end
    end
    return nil
end

function Node:find_handler(method)
    method = string_lower(method)
    if not self.handlers or not self.handlers[method] or #self.handlers[method] == 0 then
        return false
    end

    return true
end

function Node:use(...)
    local middlewares = {...}
    if not next(middlewares) then
        error("middleware should not be nil or empty")
    end

    local empty = true
    for _, h in ipairs(middlewares) do
        if type(h) == "function" then
            local action = ActionHolder:new(h, self, "middleware")
            table_insert(self.middlewares, action)
            empty = false
        elseif type(h) == "table" then
            for _, hh in ipairs(h) do
                if type(hh) == "function" then
                    local action = ActionHolder:new(hh, self, "middleware")
                    table_insert(self.middlewares, action)
                    empty = false
                else
                    error(middlware_error_tip)
                end
            end
        else
            error(middlware_error_tip)
        end
    end

    if empty then
        error("middleware should not be empty")
    end

    return self
end

function Node:error_use(...)
    local middlewares = {...}
    if not next(middlewares) then
        error("error middleware should not be nil or empty")
    end

    local empty = true
    for _, h in ipairs(middlewares) do
        if type(h) == "function" then
            local action = ActionHolder:new(h, self, "error_middleware")
            table_insert(self.error_middlewares, action)
            empty = false
        elseif type(h) == "table" then
            for _, hh in ipairs(h) do
                if type(hh) == "function" then
                    local action = ActionHolder:new(hh, self, "error_middleware")
                    table_insert(self.error_middlewares, action)
                    empty = false
                else
                    error(error_middlware_error_tip)
                end
            end
        else
            error(error_middlware_error_tip)
        end
    end

    if empty then
        error("error middleware should not be empty")
    end

    return self
end

function Node:handle(method, ...)
    method = string_lower(method)
    if not check_method(method) then
        error("error method: ", method or "nil")
    end

    if self:find_handler(method) then
        error("[" .. self.pattern .. "] " .. method .. " handler exists yet!")
    end

    if not self.handlers[method] then
        self.handlers[method] = {}
    end

    local empty = true
    local handlers = {...}
    if not next(handlers) then
        error("handler should not be nil or empty")
    end

    for _, h in ipairs(handlers) do
        if type(h) == "function" then
            local action = ActionHolder:new(h, self, "handler")
            table_insert(self.handlers[method], action)
            empty = false
        elseif type(h) == "table" then
            for _, hh in ipairs(h) do
                if type(hh) == "function" then
                    local action = ActionHolder:new(hh, self, "handler")
                    table_insert(self.handlers[method], action)
                    empty = false
                else
                    error(handler_error_tip)
                end
            end
        else
            error(handler_error_tip)
        end
    end

    if empty then
        error("handler should not be empty")
    end

    if self.allow == "" then
        self.allow = method
    else
        self.allow = self.allow .. ", " .. method
    end

    return self
end

function Node:get_allow()
    return self.allow
end

function Node:remove_nested_property(node)
    if not node then return end
    if node.parent then
        node.parent = nil
    end

    if node.colon_child then
        if node.colon_child.handlers then
            for _, h in pairs(node.colon_child.handlers) do
                if h then
                    for _, action in ipairs(h) do
                        action.func = nil
                        action.node = nil
                    end
                end
            end
        end
        self:remove_nested_property(node.colon_child)
    end

    local children = node.children
    if children and #children > 0 then
        for _, v in ipairs(children) do
            local c = v.val
            if c.handlers then -- remove action func
                for _, h in pairs(c.handlers) do
                    if h then
                        for _, action in ipairs(h) do
                            action.func = nil
                            action.node = nil
                        end
                    end
                end
            end

            self:remove_nested_property(v.val)
        end
    end
end

return Node
