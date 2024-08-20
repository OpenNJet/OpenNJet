local _M = {}

local cjson = require("cjson")
local tokenLib=require("njt.token")
local base=require("api_gateway.access.base")
local userDao = require("api_gateway.dao.user")
local config = require("api_gateway.config.config")

local RETURN_CODE = {
    SUCCESS = 0,
    PARAM_USERNAME_NOT_FOUND = 10,
    USER_QUERY_FAIL = 20, 
}

function _M.check(apiObj) 
    local retObj={}
    local args = njt.req.get_uri_args()

    local username = args["username"] or args["userName"]
   
    if not username or username == "" then
        retObj.code = RETURN_CODE.PARAM_USERNAME_NOT_FOUND
        retObj.msg = "username not found in url query parameter"
        njt.status = njt.HTTP_UNAUTHORIZED
        njt.say(cjson.encode(retObj))
        return njt.exit(njt.status)
    end

    -- get token from session
    local token_key= "param_username_token_"..username
    local rc, tv_str=tokenLib.token_get(token_key)
    
    local refresh_token= args["refresh_token"] or args["refreshToken"]
    if refresh_token and string.lower(refresh_token) == "true" then
        tv_str =""
    end

    if rc ~= 0 or not tv_str or tv_str == "" then 
        --query user/roles and set tokens
        local ok, userObj = userDao.getUserByName(username)
        if not ok then
            retObj.code = RETURN_CODE.USER_QUERY_FAIL
            retObj.msg = userObj -- second parameter is error msg when error occur
            njt.status = njt.HTTP_UNAUTHORIZED
            njt.say(cjson.encode(retObj))
            return njt.exit(njt.status)
        else
            local tv={}  -- token value
            tv.u = userObj.id
            -- set token into session
            local ok, rolesObj = userDao.getUserRoleRel(userObj.id)
            if ok then 
                tv.r = rolesObj.roles
                tv_str=cjson.encode(tv)
                local tv_str_to_be_set = tv_str 
                -- if token value's length is more than 512 bytes, will get roles later 
                if string.len(tv_str_to_be_set) > 512 then
                    tv.r = nil
                    tv_str_to_be_set=cjson.encode(tv)
                end
                tokenLib.token_set(token_key, tv_str_to_be_set, config.token_lifetime)
            end
        end
    end 

    base.verifyToken(tv_str, apiObj)
end

return _M