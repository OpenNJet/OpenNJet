local utils = require("lor.lib.utils.utils")
local ActionHolder = {}

function ActionHolder:new(func, node, action_type)
    local instance = {
        id = "action-" .. utils.random(),
        node = node,
        action_type = action_type,
        func = func,
    }

    setmetatable(instance, {
        __index = self,
        __call = self.func
    })
    return instance
end


local NodeHolder = {}

function NodeHolder:new()
    local instance = {
        key = "",
        val = nil, -- Node
    }
    setmetatable(instance, { __index = self })
    return instance
end

local Matched = {}

function Matched:new()
    local instance = {
        node = nil,
        params = {},
        pipeline = {},
    }
    setmetatable(instance, { __index = self })
    return instance
end


return {
    ActionHolder = ActionHolder,
    NodeHolder = NodeHolder,
    Matched = Matched
}
