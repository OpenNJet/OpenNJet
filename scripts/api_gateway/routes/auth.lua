local lor = require("lor.index")
local cjson = require("cjson")
local uuid = require("api_gateway.utils.uuid")
local config = require("api_gateway.config.config")
local authDao = require("api_gateway.dao.auth")

local authRouter = lor:Router()

local RETURN_CODE = {
    SUCCESS = 0,
    WRONG_POST_DATA = 10,
    LOGIN_FAIL = 20, 
    STORE_TOKEN_FAIL = 30,
}

local function loginFunc(req, res, next)
    local loginService = nil
    local retObj = {}
    local inputObj = nil

    local ok, decodedObj = pcall(cjson.decode, req.body_raw)
    if not ok then
        retObj.code = RETURN_CODE.WRONG_POST_DATA
        retObj.msg = "post data is not a valid json"
        goto LOGIN_FINISH
    else
        inputObj = decodedObj
    end

    if inputObj then
        if not inputObj.login_data then
            retObj.code = RETURN_CODE.WRONG_POST_DATA
            retObj.msg = "login_data is mandatory"
            goto LOGIN_FINISH
        end

        if not inputObj.api_group_name or not inputObj.login_type or inputObj.login_type == "internal" then
            loginService = require("api_gateway.service.internal_login")
        else
            -- create login service object based on login_type
        end
        if loginService then
            local ok, role_ids = loginService.login(inputObj.login_data)
            if ok then
                local role_ids_str = table.concat(role_ids, ",")
                -- generate uuid as token
                uuid.seed()
                local uuid_str = uuid()
                local expire = njt.time() + config.token_lifetime
                -- store token into table
                local ok, msg = authDao.storeToken(uuid_str, expire, role_ids_str)
                if ok then 
                    retObj.code = RETURN_CODE.SUCCESS
                    retObj.msg = "success"
                    retObj.token = uuid_str
                else 
                    retObj.code = RETURN_CODE.STORE_TOKEN_FAIL
                    retObj.msg = msg
                end
            else
                retObj.code = RETURN_CODE.LOGIN_FAIL
                retObj.msg = role_ids -- second parameter is the error msg    
            end
        end
    end

    ::LOGIN_FINISH::
    res:json(retObj, true)
end

authRouter:post("/login", loginFunc)

return authRouter
