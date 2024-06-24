local pairs = pairs
local ipairs = ipairs
local pcall = pcall
local xpcall = xpcall
local type = type
local error = error
local setmetatable = setmetatable
local traceback = debug.traceback
local tinsert = table.insert
local table_concat = table.concat
local string_format = string.format
local string_lower = string.lower

local utils = require("lor.lib.utils.utils")
local supported_http_methods = require("lor.lib.methods")
local debug = require("lor.lib.debug")
local Trie = require("lor.lib.trie")
local random = utils.random
local mixin = utils.mixin

local allowed_conf = {
    strict_route = {
        t = "boolean"
    },
    ignore_case = {
        t = "boolean"
    },
    max_uri_segments = {
        t = "number"
    },
    max_fallback_depth = {
        t = "number"
    },
}

local function restore(fn, obj)
    local origin = {
        path = obj['path'],
        query = obj['query'],
        next = obj['next'],
        locals = obj['locals'],
    }

    return function(err)
        obj['path'] = origin.path
        obj['query'] = origin.query
        obj['next'] = origin.next
        obj['locals'] = origin.locals
        fn(err)
    end
end

local function compose_func(matched, method)
    if not matched or type(matched.pipeline) ~= "table" then
        return nil
    end

    local exact_node = matched.node
    local pipeline = matched.pipeline or {}
    if not exact_node or not pipeline then
        return nil
    end

    local stack = {}
    for _, p in ipairs(pipeline) do
        local middlewares = p.middlewares
        local handlers = p.handlers
        if middlewares then
            for _, middleware in ipairs(middlewares) do
                tinsert(stack, middleware)
            end
        end

        if p.id == exact_node.id and handlers and handlers[method] then
            for _, handler in ipairs(handlers[method]) do
                tinsert(stack, handler)
            end
        end
    end

    return stack
end

local function compose_error_handler(node)
    if not node then
        return nil
    end

    local stack = {}
    while node do
        for _, middleware in ipairs(node.error_middlewares) do
            tinsert(stack, middleware)
        end
        node = node.parent
    end

    return stack
end


local Router = {}

function Router:new(options)
    local opts = options or {}
    local router = {}

    router.name =  "router-" .. random()
    router.trie = Trie:new({
        ignore_case = opts.ignore_case,
        strict_route = opts.strict_route,
        max_uri_segments = opts.max_uri_segments,
        max_fallback_depth = opts.max_fallback_depth
    })

    self:init()
    setmetatable(router, {
        __index = self,
        __tostring = function(s)
            local ok, result = pcall(function()
                return string_format("name: %s", s.name)
            end)
            if ok then
                return result
            else
                return "router.tostring() error"
            end
        end
    })

    return router
end

--- a magick to convert `router()` to `router:handle()`
-- so a router() could be regarded as a `middleware`
function Router:call()
    return function(req, res, next)
        return self:handle(req, res, next)
    end
end

-- dispatch a request
function Router:handle(req, res, out)
    local path = req.path
    if not path or path == "" then
        path = ""
    end
    local method = req.method and string_lower(req.method)
    local done = out

    local stack = nil
    local matched = self.trie:match(path)
    local matched_node = matched.node

    if not method or not matched_node then
        if res.status then res:status(404) end
        return self:error_handle("404! not found.", req, res, self.trie.root, done)
    else
        local matched_handlers = matched_node.handlers and matched_node.handlers[method]
        if not matched_handlers or #matched_handlers <= 0 then
            return self:error_handle("Oh! no handler to process method: " .. method, req, res, self.trie.root, done)
        end

        stack = compose_func(matched, method)
        if not stack or #stack <= 0 then
            return self:error_handle("Oh! no handlers found.", req, res, self.trie.root, done)
        end
    end

    local stack_len = #stack
    req:set_found(true)
    local parsed_params = matched.params or {} -- origin params, parsed
    req.params = parsed_params

    local idx = 0
    local function next(err)
        if err then
            return self:error_handle(err, req, res, stack[idx].node, done)
        end

        if idx > stack_len then
            return done(err) -- err is nil or not
        end

        idx = idx + 1
        local handler = stack[idx]
        if not handler then
            return done(err)
        end

        local err_msg
        local ok, ee = xpcall(function()
            handler.func(req, res, next)
            req.params = mixin(parsed_params, req.params)
        end, function(msg)
            if msg then
                if type(msg) == "string" then
                    err_msg = msg
                elseif type(msg) == "table" then
                    err_msg = "[ERROR]" .. table_concat(msg, "|") .. "[/ERROR]"
                end
            else
                err_msg = ""
            end
            err_msg = err_msg .. "\n" .. traceback()
        end)

        if not ok then
            --debug("handler func:call error ---> to error_handle,", ok, "err_msg:", err_msg)
            return self:error_handle(err_msg, req, res, handler.node, done)
        end
    end

    next()
end

-- dispatch an error
function Router:error_handle(err_msg, req, res, node, done)
    local stack = compose_error_handler(node)
    if not stack or #stack <= 0 then
        return done(err_msg)
    end

    local idx = 0
    local stack_len = #stack
    local function next(err)
        if idx >= stack_len then
            return done(err)
        end

        idx = idx + 1
        local error_handler = stack[idx]
        if not error_handler then
            return done(err)
        end

        local ok, ee = xpcall(function()
            error_handler.func(err, req, res, next)
        end, function(msg)
            if msg then
                if type(msg) == "string" then
                    err_msg = msg
                elseif type(msg) == "table" then
                    err_msg = "[ERROR]" .. table_concat(msg, "|") .. "[/ERROR]"
                end
            else
                err_msg = ""
            end

            err_msg = string_format("%s\n[ERROR in ErrorMiddleware#%s(%s)] %s \n%s", err, idx, error_handler.id, err_msg, traceback())
        end)

        if not ok then
            return done(err_msg)
        end
    end

    next(err_msg)
end

function Router:use(path, fn, fn_args_length)
    if type(fn) == "function" then -- fn is a function
        local node
        if not path then
            node = self.trie.root
        else
            node = self.trie:add_node(path)
        end
        if fn_args_length == 3 then
            node:use(fn)
        elseif fn_args_length == 4 then
            node:error_use(fn)
        end
    elseif fn and fn.is_group == true then -- fn is a group router
        if fn_args_length ~= 3 then
            error("illegal param, fn_args_length should be 3")
        end

        path = path or "" -- if path is nil, then mount it on `root`
        self:merge_group(path, fn)
    end

    return self
end

function Router:merge_group(prefix, group)
    local apis = group:get_apis()

    if apis then
        for uri, api_methods in pairs(apis) do
            if type(api_methods) == "table" then
                local path
                if uri == "" then -- for group index route
                    path = utils.clear_slash(prefix)
                else
                    path = utils.clear_slash(prefix .. "/" .. uri)
                end

                local node = self.trie:add_node(path)
                if not node then
                    return error("cann't define node on router trie, path:" .. path)
                end

                for method, handlers in pairs(api_methods) do
                    local m = string_lower(method)
                    if supported_http_methods[m] == true then
                        node:handle(m, handlers)
                    end -- supported method
                end
            end
        end
    end -- ugly arrow style for missing `continue`

    return self
end

function Router:app_route(http_method, path, ...)
    local node = self.trie:add_node(path)
    node:handle(http_method, ...)
    return self
end

function Router:init()
    for http_method, _ in pairs(supported_http_methods) do
        self[http_method] = function(s, path, ...)
            local node = s.trie:add_node(path)
            node:handle(http_method, ...)
            return s
        end
    end
end

function Router:conf(setting, val)
    local allow = allowed_conf[setting]
    if allow then
        if allow.t == "boolean" then

            if val == "true" or val == true then
                self.trie[setting] = true
            elseif val == "false" or val == false then
                self.trie[setting] = false
            end
        elseif allow.t == "number" then
            val = tonumber(val)
            self.trie[setting] = val or self[setting]
        end
    end

    return self
end

return Router
