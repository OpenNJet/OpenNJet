-- https://github.com/api7/lua-resty-radixtree
--
-- Copyright 2020 Shenzhen ZhiLiu Technology Co., Ltd.
-- https://www.apiseven.com
--
-- See the NOTICE file distributed with
-- this work for additional information regarding copyright ownership.
-- The owner licenses this file to You under the Apache License, Version 2.0;
-- you may not use this file except in compliance with
-- the License. You may obtain a copy of the License at
--
--    http://www.apache.org/licenses/LICENSE-2.0
--
-- Unless required by applicable law or agreed to in writing, software
-- distributed under the License is distributed on an "AS IS" BASIS,
-- WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
-- See the License for the specific language governing permissions and
-- limitations under the License.
--
local ipairs      = ipairs
local setmetatable = setmetatable
local tonumber    = tonumber
local type = type
local str_upper = string.upper
local str_lower = string.lower
local new_tab     = require("table.new")
local re_find     = ngx.re.find
local ngx_var     = ngx.var
local ngx_null    = ngx.null
local ipmatcher   = require("resty.ipmatcher")


local _M = {}
local mt = { __index = _M }
local not_op = "!"


local function in_array(l_v, r_v)
    if type(r_v) == "table" then
        for _,v in ipairs(r_v) do
            if v == l_v then
                return true
            end
        end
    end
    return false
end


local function has_element(l_v, r_v)
    if type(l_v) == "table" then
        for _, v in ipairs(l_v) do
            if v == r_v then
                return true
            end
        end

        return false
    end

    return false
end



local function ip_match(l_v, r_v)
    return r_v:match(l_v)
end


local compare_funcs = {
    ["=="] = function (l_v, r_v)
        if type(r_v) == "number" then
            l_v = tonumber(l_v)
            if not l_v then
                return false
            end
        end
        return l_v == r_v
    end,
    ["~="] = function (l_v, r_v)
        if type(r_v) == "number" then
            l_v = tonumber(l_v)
            if not l_v then
                return true
            end
        end
        return l_v ~= r_v
    end,
    [">"] = function (l_v, r_v)
        l_v = tonumber(l_v)
        r_v = tonumber(r_v)
        if not l_v or not r_v then
            return false
        end
        return l_v > r_v
    end,
    [">="] = function (l_v, r_v)
        l_v = tonumber(l_v)
        r_v = tonumber(r_v)
        if not l_v or not r_v then
            return false
        end
        return l_v >= r_v
    end,
    ["<"] = function (l_v, r_v)
        l_v = tonumber(l_v)
        r_v = tonumber(r_v)
        if not l_v or not r_v then
            return false
        end
        return l_v < r_v
    end,
    ["<="] = function (l_v, r_v)
        l_v = tonumber(l_v)
        r_v = tonumber(r_v)
        if not l_v or not r_v then
            return false
        end
        return l_v <= r_v
    end,
    ["~~"] = function (l_v, r_v)
        if not l_v then
            return false
        end

        local from = re_find(l_v, r_v, "jo")
        if from then
            return true
        end
        return false
    end,
    ["~*"] = function (l_v, r_v)
        if not l_v then
            return false
        end

        local from = re_find(l_v, r_v, "joi")
        if from then
            return true
        end
        return false
    end,
    ["in"] = in_array,
    ["has"] = has_element,
    ["ipmatch"] = ip_match,
}


local function compare_val(l_v, op, r_v)
    if r_v == ngx_null then
        r_v = nil
    end

    local com_fun = compare_funcs[op]
    if not com_fun then
        return false
    end
    return com_fun(l_v, r_v)
end


local function compile_expr(expr)
    local l_v, op, r_v
    local reverse = false

    if #expr == 4 then
        if expr[2] ~= not_op then
            return nil, "bad 'not' expression"
        end

        reverse = true
        l_v, op, r_v = expr[1], expr[3], expr[4]
    else
        l_v, op, r_v = expr[1], expr[2], expr[3]
    end

    if op ~= nil then
        op = str_lower(op)
    end

    if r_v == nil and not compare_funcs[op] then
        -- for compatibility
        r_v = op
        op = "=="

        if r_v == nil then
            return nil, "invalid expression"
        end
    end

    if l_v == nil or op == nil then
        return nil, "invalid expression"
    end

    if compare_funcs[op] == nil then
        return nil, "invalid operator '" .. op .. "'"
    end

    if op == "ipmatch" then
        if not r_v or r_v == "" then
            return nil, "invalid ip address"
        end
        if type(r_v) ~= "table" then
            r_v = { r_v }
        end

        if #r_v == 0 then
            return nil, "invalid ip address"
        end

        local ip, err = ipmatcher.new(r_v)
        if not ip then
            return false, err
        end

        r_v = ip
    end

    return {
        l_v = l_v,
        op = op,
        r_v = r_v,
        reverse = reverse,
    }
end


local logic_ops = {
    ["OR"] = true,
    ["!OR"] = true,
    ["AND"] = true,
    ["!AND"] = true,
}


local function compile(rules)
    local n_rule = #rules
    if n_rule <= 0 then
        return nil, "rule too short"
    end

    local compiled = {
        logic_op = "AND",
        exprs = new_tab(n_rule, 0),
    }

    if type(rules[1]) == "table" then
        for i, expr in ipairs(rules) do
            local res, err = compile(rules[i])
            if not res then
                return nil, err
            end

            compiled.exprs[i] = res
        end
        return compiled
    end

    local op = str_upper(rules[1])
    if logic_ops[op] then
        compiled.logic_op = op
        if n_rule <= 2 then
            return nil, "rule too short"
        end

        for i = 2, n_rule do
            local res, err = compile(rules[i])
            if not res then
                return nil, err
            end

            compiled.exprs[i - 1] = res
        end

        return compiled
    end

    return compile_expr(rules)
end


function _M.new(rule)
    if not rule then
        return nil, "missing argument rule"
    end

    local n_rule = #rule
    if n_rule == 0 then
        return setmetatable({}, mt)
    end

    if type(rule[1]) ~= "table" then
        local op = str_upper(rule[1])
        if not logic_ops[op] then
            return nil, "rule should be wrapped inside brackets"
        end
    end

    local compiled, err = compile(rule)
    if not compiled then
        return nil, err
    end

    return setmetatable({rule = compiled}, mt)
end


local eval
-- '...' is chosen for backward compatibility, for instance, we need to pass
-- `opts` argument in lua-resty-radixtree
local function eval_and(ctx, exprs, ...)
    for _, expr in ipairs(exprs) do
        if expr.logic_op then
            if not eval(ctx, expr, ...) then
                return false
            end
        else
            local l_v = ctx[expr.l_v]

            if compare_val(l_v, expr.op, expr.r_v, ...) == expr.reverse then
                return false
            end
        end
    end

    return true
end


local function eval_or(ctx, exprs, ...)
    for _, expr in ipairs(exprs) do
        if expr.logic_op then
            if eval(ctx, expr, ...) then
                return true
            end
        else
            local l_v = ctx[expr.l_v]

            if compare_val(l_v, expr.op, expr.r_v, ...) ~= expr.reverse then
                return true
            end
        end
    end

    return false
end


eval = function(ctx, compiled, ...)
    if compiled.logic_op == "AND" then
        return eval_and(ctx, compiled.exprs, ...)
    end

    if compiled.logic_op == "OR" then
        return eval_or(ctx, compiled.exprs, ...)
    end

    if compiled.logic_op == "!AND" then
        return not eval_and(ctx, compiled.exprs, ...)
    end

    if compiled.logic_op == "!OR" then
        return not eval_or(ctx, compiled.exprs, ...)
    end

    error("unknown logic operator: " .. (compiled.logic_op or "nil"))
end


function _M.eval(self, ctx, ...)
    if not self.rule then
        return true
    end

    local ctx = ctx or ngx_var
    if type(ctx) ~= "table" then
        return nil, "bad ctx type"
    end

    return eval(ctx, self.rule, ...)
end


return _M
