local setmetatable = setmetatable

local _M = {}

function _M:new(create_app, Router, Group, Request, Response)
    local instance = {}
    instance.router = Router
    instance.group = Group
    instance.request = Request
    instance.response = Response
    instance.fn = create_app
    instance.app = nil

    setmetatable(instance, {
        __index = self,
        __call = self.create_app
    })

    return instance
end

-- Generally, this should only be used by `lor` framework itself.
function _M:create_app(options)
    self.app = self.fn(options)
    return self.app
end

function _M:Router(options)
    return self.group:new(options)
end

function _M:Request()
    return self.request:new()
end

function _M:Response()
    return self.response:new()
end

return _M
