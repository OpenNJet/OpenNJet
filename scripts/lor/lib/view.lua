local pairs = pairs
local type = type
local setmetatable = setmetatable
local tostring = tostring
local template = require "resty.template"
local template_new = template.new

local View = {}

function View:new(view_config)
    local instance = {}
    instance.view_enable = view_config.view_enable
    if instance.view_enable then
        if njt.var.template_root then
            njt.var.template_root =  view_config.views
        else
            njt.log(njt.ERR, "$template_root is not set in nginx.conf")
        end
    end
    instance.view_engine = view_config.view_engine
    instance.view_ext = view_config.view_ext
    instance.view_layout = view_config.view_layout
    instance.views = view_config.views

    setmetatable(instance, {__index = self})
    return instance
end

function View:caching()
end

-- to optimize
function View:render(view_file, data)
    if not self.view_enable then
        njt.log(njt.ERR, "view is not enabled. you may need `app:conf('view enable', true)`")
    else
        local view_file_name = view_file .. "." .. self.view_ext
        local layout_file_name = self.view_layout .. "." .. self.view_ext

        local t = template_new(view_file_name)
        if self.view_layout ~= "" then
            t = template_new(view_file_name,layout_file_name)
        end
        if data and type(data) == 'table' then
            for k,v in pairs(data) do
                t[k] = v
            end
        end

        return tostring(t)
    end
end

return View