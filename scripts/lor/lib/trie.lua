local setmetatable = setmetatable
local tonumber = tonumber
local string_lower = string.lower
local string_find = string.find
local string_sub = string.sub
local string_gsub = string.gsub
local string_len = string.len
local string_format = string.format
local table_insert = table.insert
local table_remove = table.remove
local table_concat = table.concat

local utils = require("lor.lib.utils.utils")
local holder = require("lor.lib.holder")
local Node = require("lor.lib.node")
local NodeHolder = holder.NodeHolder
local Matched = holder.Matched
local mixin = utils.mixin
local valid_segment_tip = "valid path should only contains: [A-Za-z0-9._%-~]"


local function check_segment(segment)
    local tmp = string_gsub(segment, "([A-Za-z0-9._%%-~]+)", "")
    if tmp ~= "" then
        return false
    end
    return true
end

local function check_colon_child(node, colon_child)
    if not node or not colon_child then
        return false, nil
    end

    if node.name ~= colon_child.name or node.regex ~= colon_child.regex then
        return false, colon_child
    end

    return true, nil -- could be added
end

local function get_or_new_node(parent, frag, ignore_case)
    if not frag or frag == "/" or frag == "" then
        frag = ""
    end

    if ignore_case == true then
        frag = string_lower(frag)
    end

    local node = parent:find_child(frag)
    if node then
        return node
    end

    node = Node:new()
    node.parent = parent

    if frag == "" then
        local nodePack = NodeHolder:new()
        nodePack.key = frag
        nodePack.val = node
        table_insert(parent.children, nodePack)
    else
        local first = string_sub(frag, 1, 1)
        if first ==  ":" then
            local name = string_sub(frag, 2)
            local trailing = string_sub(name, -1)

            if trailing == ')' then
                local index = string_find(name, "%(")
                if index and index > 1 then
                    local regex = string_sub(name, index+1, #name-1)
                    if #regex > 0 then
                        name = string_sub(name, 1, index-1 )
                        node.regex = regex
                    else
                        error("invalid pattern[1]: " .. frag)
                    end
                end
            end

            local is_name_valid = check_segment(name)
            if not is_name_valid then
                error("invalid pattern[2], illegal path:" .. name .. ", " .. valid_segment_tip)
            end
            node.name = name

            local colon_child = parent.colon_child
            if colon_child then
                local valid, conflict = check_colon_child(node, colon_child)
                if not valid then
                    error("invalid pattern[3]: [" .. name .. "] conflict with [" .. conflict.name .. "]")
                else
                    return colon_child
                end
            end

            parent.colon_child = node
        else
            local is_name_valid = check_segment(frag)
            if not is_name_valid then
                error("invalid pattern[6]: " .. frag .. ", " .. valid_segment_tip)
            end

            local nodePack = NodeHolder:new()
            nodePack.key = frag
            nodePack.val = node
            table_insert(parent.children, nodePack)
        end
    end

    return node
end

local function insert_node(parent, frags, ignore_case)
    local frag = frags[1]
    local child = get_or_new_node(parent, frag, ignore_case)

    if #frags >= 1 then
        table_remove(frags, 1)
    end

    if #frags == 0 then
        child.endpoint = true
        return child
    end

    return insert_node(child, frags, ignore_case)
end

local function get_pipeline(node)
    local pipeline = {}
    if not node then return pipeline end

    local tmp = {}
    local origin_node = node
    table_insert(tmp, origin_node)
    while node.parent
    do
        table_insert(tmp, node.parent)
        node = node.parent
    end

    for i = #tmp, 1, -1 do
        table_insert(pipeline, tmp[i])
    end

    return pipeline
end


local Trie = {}

function Trie:new(opts)
    opts = opts or {}
    local trie = {
        -- limit to avoid dead `while` or attack for fallback lookup
        max_fallback_depth = 100, 

        -- limit to avoid uri attack. e.g. a long uri, /a/b/c/d/e/f/g/h/i/j/k...
        max_uri_segments = 100,
        
        -- should ignore case or not
        ignore_case = true, 

        -- [true]: "test.com/" is not the same with "test.com".
        -- [false]: "test.com/" will match "test.com/" first, then try to math "test.com" if not exists 
        strict_route = true,

        -- the root node of this trie structure
        root = Node:new(true)
    }

    trie.max_fallback_depth = tonumber(opts.max_fallback_depth) or trie.max_fallback_depth
    trie.max_uri_segments = tonumber(opts.max_uri_segments) or trie.max_uri_segments
    trie.ignore_case = opts.ignore_case or trie.ignore_case
    trie.strict_route = not (opts.strict_route == false)

    setmetatable(trie, {
        __index = self,
        __tostring = function(s)
            return string_format("Trie, ignore_case:%s strict_route:%s max_uri_segments:%d max_fallback_depth:%d",
                s.ignore_case, s.strict_route, s.max_uri_segments, s.max_fallback_depth)
        end
    })

    return trie
end

function Trie:add_node(pattern)
    pattern = utils.trim_path_spaces(pattern)

    if string_find(pattern, "//") then
        error("`//` is not allowed: " ..  pattern)
    end

    local tmp_pattern = utils.trim_prefix_slash(pattern)
    local tmp_segments = utils.split(tmp_pattern, "/")

    local node = insert_node(self.root, tmp_segments, self.ignore_case)
    if node.pattern == "" then
        node.pattern = pattern
    end

    return node
end

--- get matched colon node
function Trie:get_colon_node(parent, segment)
    local child = parent.colon_child
    if child and child.regex and not utils.is_match(segment, child.regex) then
        child = nil -- illegal & not mathed regrex
    end
    return child
end

--- retry to fallback to lookup the colon nodes in `stack`
function Trie:fallback_lookup(fallback_stack, segments, params)
    if #fallback_stack == 0 then
        return false
    end

    local fallback = table_remove(fallback_stack, #fallback_stack)
    local segment_index = fallback.segment_index
    local parent = fallback.colon_node
    local matched = Matched:new()

    if parent.name ~= "" then -- fallback to the colon node and fill param if matched
        matched.params[parent.name] = segments[segment_index]
    end
    mixin(params, matched.params) -- mixin params parsed before

    local flag = true
    for i, s in ipairs(segments) do
        if i <= segment_index then -- mind: should use <= not <
            -- continue
        else
            local node, colon_node, is_same = self:find_matched_child(parent, s)
            if self.ignore_case and node == nil then
                node, colon_node, is_same = self:find_matched_child(parent, string_lower(s))
            end

            if colon_node and not is_same then
                -- save colon node to fallback stack
                table_insert(fallback_stack, {
                    segment_index = i,
                    colon_node = colon_node
                })
            end

            if node == nil then -- both exact child and colon child is nil
                flag = false -- should not set parent value
                break
            end

            parent = node
        end
    end

    if flag and parent.endpoint then
        matched.node = parent
        matched.pipeline = get_pipeline(parent)
    end

    if matched.node then
        return matched
    else
        return false
    end
end

--- find exactly mathed node and colon node
function Trie:find_matched_child(parent, segment)
    local child = parent:find_child(segment)
    local colon_node = self:get_colon_node(parent, segment)

    if child then
        if colon_node then
            return child, colon_node, false
        else
            return child, nil, false
        end
    else -- not child
        if colon_node then
            return colon_node, colon_node, true -- 后续不再压栈
        else
            return nil, nil, false
        end
    end
end

function Trie:match(path)
    if not path or path == "" then
        error("`path` should not be nil or empty")
    end

    path = utils.slim_path(path)

    local first = string_sub(path, 1, 1)
    if first ~= '/' then
        error("`path` is not start with prefix /: " .. path)
    end

    if path == "" then -- special case: regard "test.com" as "test.com/"
        path = "/"
    end

    local matched = self:_match(path)
    if not matched.node and self.strict_route ~= true then
        if string_sub(path, -1) == '/' then -- retry to find path without last slash
            matched = self:_match(string_sub(path, 1, -2))
        end
    end

    return matched
end

function Trie:_match(path)
    local start_pos = 2
    local end_pos = string_len(path) + 1
    local segments = {}
    for i = 2, end_pos, 1 do -- should set max depth to avoid attack
        if i < end_pos and string_sub(path, i, i) ~= '/' then
            -- continue
        else
            local segment = string_sub(path, start_pos, i-1)
            table_insert(segments, segment)
            start_pos = i + 1
        end
    end

    local flag = true -- whether to continue to find matched node or not
    local matched = Matched:new()
    local parent = self.root
    local fallback_stack = {}
    for i, s in ipairs(segments) do
        local node, colon_node, is_same = self:find_matched_child(parent, s)
        if self.ignore_case and node == nil then
            node, colon_node, is_same = self:find_matched_child(parent, string_lower(s))
        end

        if colon_node and not is_same then
            table_insert(fallback_stack, {
                segment_index = i,
                colon_node = colon_node
            })
        end

        if node == nil then -- both exact child and colon child is nil
            flag = false -- should not set parent value
            break
        end

        parent = node
        if parent.name ~= "" then
            matched.params[parent.name] = s
        end
    end

    if flag and parent.endpoint then
        matched.node = parent
    end

    local params = matched.params or {}
    if not matched.node then
        local depth = 0
        local exit = false

        while not exit do
            depth = depth + 1
            if depth > self.max_fallback_depth then
                error("fallback lookup reaches the limit: " .. self.max_fallback_depth)
            end

            exit = self:fallback_lookup(fallback_stack, segments, params)
            if exit then
                matched = exit
                break
            end

            if #fallback_stack == 0 then
                break
            end
        end
    end

    matched.params = params
    if matched.node then
        matched.pipeline = get_pipeline(matched.node)
    end

    return matched
end

--- only for dev purpose: pretty json preview
-- must not be invoked in runtime
function Trie:remove_nested_property(node)
    if not node then return end
    if node.parent then
        node.parent = nil
    end
    if node.handlers then
        for _, h in pairs(node.handlers) do
            if h then
                for _, action in ipairs(h) do
                    action.func = nil
                    action.node = nil
                end
            end
        end
    end
    if node.middlewares then
        for _, m in pairs(node.middlewares) do
            if m then
                m.func = nil
                m.node = nil
            end
        end
    end
    if node.error_middlewares then
        for _, m in pairs(node.error_middlewares) do
            if m then
                m.func = nil
                m.node = nil
            end
        end
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
        if node.colon_child.middlewares then
            for _, m in pairs(node.colon_child.middlewares) do
                if m then
                    m.func = nil
                    m.node = nil
                end
            end
        end
        if node.colon_child.error_middlewares then
            for _, m in pairs(node.colon_child.error_middlewares) do
                if m then
                    m.func = nil
                    m.node = nil
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
            if c.middlewares then
                for _, m in pairs(c.middlewares) do
                    if m then
                        m.func = nil
                        m.node = nil
                    end
                end
            end
            if c.error_middlewares then
                for _, m in pairs(c.error_middlewares) do
                    if m then
                        m.func = nil
                        m.node = nil
                    end
                end
            end

            self:remove_nested_property(v.val)
        end
    end
end

--- only for dev purpose: graph preview
-- must not be invoked in runtime
function Trie:gen_graph()
    local cloned_trie = utils.clone(self)
    cloned_trie:remove_nested_property(cloned_trie.root)
    local result = {"graph TD",  cloned_trie.root.id .. "((root))"}

    local function recursive_draw(node, res)
        if node.is_root then node.key = "root" end

        local colon_child = node.colon_child
        if colon_child then
            table_insert(res, node.id .. "-->" .. colon_child.id .. "(:" .. colon_child.name .. "<br/>" .. colon_child.id .. ")")
            recursive_draw(colon_child, res)
        end

        local children = node.children
        if children and #children > 0 then
            for _, v in ipairs(children) do
                if v.key == "" then
                    --table_insert(res, node.id .. "-->" .. v.val.id .. "[*EMPTY*]")
                    local text = {node.id, "-->", v.val.id, "(<center>", "*EMPTY*", "<br/>", v.val.id, "</center>)"}
                    table_insert(res, table_concat(text, ""))
                else
                    local text = {node.id, "-->", v.val.id, "(<center>", v.key, "<br/>", v.val.id, "</center>)"}
                    table_insert(res, table_concat(text, ""))
                end
                recursive_draw(v.val, res)
            end
        end
    end

    recursive_draw(cloned_trie.root, result)
    return table.concat(result, "\n")
end

return Trie
