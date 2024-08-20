local lor = require("lor.index")
local cjson = require("cjson")
local socket = require("socket")
local uuid = require("api_gateway.utils.uuid")
local util = require("api_gateway.utils.util")
local config = require("api_gateway.config.config")
local authDao = require("api_gateway.dao.auth")
local userDao = require("api_gateway.dao.user")
local random = require("resty.random")
local emailSrv = require("api_gateway.service.email")
local tokenLib = require("njt.token")

local authRouter = lor:Router()

local RETURN_CODE = {
    SUCCESS = 0,
    WRONG_POST_DATA = 10,
    LOGIN_FAIL = 20,
    STORE_TOKEN_FAIL = 30,
    EMAIL_NOT_FOUND = 40, 
    EMAIL_SENT_FAIL = 50, 
    VERIFY_CDOE_STORE_ERROR = 60,
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
            -- TODO: create login service object based on login_type, such as external
        end
        if loginService then
            local ok, userId = loginService.login(inputObj.login_data)
            if ok then
                -- generate uuid as token
                uuid.seed()
                local uuidStr = uuid()
                local expire = njt.time() + config.token_lifetime
                -- set token into session
                local ok, rolesObj = userDao.getUserRoleRel(userId)
                if not ok then
                    retObj.code = RETURN_CODE.LOGIN_FAIL
                    retObj.msg = "can't found the user'roles in db"
                else
                    local tv={}  -- token value
                    tv.u = userId
                    tv.r = rolesObj.roles
                    local tv_str=cjson.encode(tv)
                    -- if token value's length is more than 512 bytes, will get roles later 
                    if string.len(tv_str) > 512 then
                        tv.r = nil
                        tv_str=cjson.encode(tv)
                    end
                    local rc, msg = tokenLib.token_set(uuidStr, tv_str, config.token_lifetime)
                    -- local ok, msg = authDao.storeToken(uuidStr, expire, role_ids_str)
                    if rc == 0 then
                        retObj.code = RETURN_CODE.SUCCESS
                        retObj.msg = "success"
                        retObj.token = uuidStr
                    else
                        retObj.code = RETURN_CODE.STORE_TOKEN_FAIL
                        retObj.msg = msg
                    end
                end
            else
                retObj.code = RETURN_CODE.LOGIN_FAIL
                retObj.msg = userId -- second parameter is the error msg    
            end
        end
    end

    ::LOGIN_FINISH::
    res:json(retObj, true)
end

local function verificationCodeFunc(req, res, next)
    local retObj={}
    local inputObj = nil

    --validate post data
    local ok, decodedObj = pcall(cjson.decode, req.body_raw)
    if not ok then
        retObj.code = RETURN_CODE.WRONG_POST_DATA
        retObj.msg = "post data is not a valid json"
        goto VERI_FINISH
    else
        inputObj = decodedObj
    end

    if inputObj then 
        --right now, only sending verification code to email is supported
        if not inputObj.email or not util.checkEmail(inputObj.email) then
            retObj.code = RETURN_CODE.WRONG_POST_DATA
            retObj.msg = "email is mandatory and should be in valid format"
            goto VERI_FINISH
        end

        local email= inputObj.email
        --valide email in api_user table
        local ok, userObj = userDao.getUserByEmail(email)
        if not ok then
            retObj.code = RETURN_CODE.EMAIL_NOT_FOUND
            retObj.msg = "can't find user with email ".. email
            goto VERI_FINISH
        end

        -- generate and insert token
        local token = random.token(6)
        local expire = njt.time() + config.verification_code_lifetime
        --local ok, msg = authDao.storeVerificationCode(email, token, expire)
        local rc, msg = tokenLib.token_set("sms_login_token_"..email, token, config.verification_code_lifetime)
        if rc ~= 0 then
            retObj.code = RETURN_CODE.VERIFY_CDOE_STORE_ERROR
            retObj.msg = msg
            goto VERI_FINISH
        end

        local ok, msg = emailSrv.send(config.email_from, email, "verification code", "The verification code is: "..token)   
        if not ok then
            retObj.code =  RETURN_CODE.EMAIL_SENT_FAIL
            retObj.msg = msg
        else 
            retObj.code =  0
            retObj.msg = "success"
        end
    end

    ::VERI_FINISH::
    res:json(retObj, true)
end

authRouter:post("/login", loginFunc)
authRouter:post("/verification", verificationCodeFunc)

return authRouter
