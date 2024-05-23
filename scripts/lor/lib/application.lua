local pairs = pairs
local type = type
local xpcall = xpcall
local setmetatable = setmetatable

local Router = require("lor.lib.router.router")
local Request = require("lor.lib.request")
local Response = require("lor.lib.response")
local View = require("lor.lib.view")
local supported_http_methods = require("lor.lib.methods")

local router_conf = {
    strict_route = true,
    ignore_case = true,
    max_uri_segments = true,
    max_fallback_depth = true
}

local App = {}

function App:new()
    local instance = {}
    instance.cache = {}
    instance.settings = {}
    instance.router = Router:new()

    setmetatable(instance, {
        __index = self,
        __call = self.handle
    })

    instance:init_method()
    return instance
end

function App:run(final_handler)
    local request = Request:new()
    local response = Response:new()

    local enable_view = self:getconf("view enable")
    if enable_view then
        local view_config = {
            view_enable = enable_view,
            view_engine = self:getconf("view engine"), -- view engine: resty-template or others...
            view_ext = self:getconf("view ext"), -- defautl is "html"
            view_layout = self:getconf("view layout"), -- defautl is ""
            views = self:getconf("views") -- template files directory
        }

        local view = View:new(view_config)
        response.view = view
    end

    self:handle(request, response, final_handler)
end

function App:init(options)
    self:default_configuration(options)
end

function App:default_configuration(options)
    options = options or {}

    -- view and template configuration
    if options["view enable"] ~= nil and options["view enable"] == true then
        self:conf("view enable", true)
    else
        self:conf("view enable", false)
    end
    self:conf("view engine", options["view engine"] or "tmpl")
    self:conf("view ext", options["view ext"] or "html")
    self:conf("view layout", options["view layout"] or "")
    self:conf("views", options["views"] or "./app/views/")

    self.locals = {}
    self.locals.settings = self.setttings
end

-- dispatch `req, res` into the pipeline.
function App:handle(req, res, callback)
    local router = self.router
    local done = callback or function(err)
        if err then
            if njt then njt.log(njt.ERR, err) end
            res:status(500):send("internal error! please check log.")
        end
    end

    if not router then
        return done()
    end

    local err_msg
    local ok, e = xpcall(function()
        router:handle(req, res, done)
    end, function(msg)
        err_msg = msg
    end)

    if not ok then
        done(err_msg)
    end
end

function App:use(path, fn)
    self:inner_use(3, path, fn)
end

-- just a mirror for `erroruse`
function App:erruse(path, fn)
    self:erroruse(path, fn)
end

function App:erroruse(path, fn)
    self:inner_use(4, path, fn)
end

-- should be private
function App:inner_use(fn_args_length, path, fn)
    local router = self.router

    if path and fn and type(path) == "string" then
        router:use(path, fn, fn_args_length)
    elseif path and not fn then
        fn = path
        path = nil
        router:use(path, fn, fn_args_length)
    else
        error("error usage for `middleware`")
    end

    return self
end

function App:init_method()
    for http_method, _ in pairs(supported_http_methods) do
        self[http_method] = function(_self, path, ...) -- funcs...
            _self.router:app_route(http_method, path, ...)
            return _self
        end
    end
end

function App:all(path, ...)
    for http_method, _ in pairs(supported_http_methods) do
        self.router:app_route(http_method, path, ...)
    end

    return self
end

function App:conf(setting, val)
    self.settings[setting] = val

    if router_conf[setting] == true then
        self.router:conf(setting, val)
    end

    return self
end

function App:getconf(setting)
    return self.settings[setting]
end

function App:enable(setting)
    self.settings[setting] = true
    return self
end

function App:disable(setting)
    self.settings[setting] = false
    return self
end

--- only for dev
function App:gen_graph()
    return self.router.trie:gen_graph()
end

return App
