local lor = require("lor.index")
local cjson = require("cjson")

local roleRouter = lor:Router()
local roleDao = require("api_gateway.dao.role")

local RETURN_CODE = {
    SUCCESS = 0,
    WRONG_POST_DATA = 10,
    ROLE_ID_INVALID = 20,
    ROLE_QUERY_FAIL = 30,
    ROLE_DELETE_FAIL = 40,
    ROLE_CREATE_FAIL = 50
}

local function createRole(req, res, next)
    local retObj = {}

    local inputObj = nil

    local ok, decodedObj = pcall(cjson.decode, req.body_raw)
    if not ok then
        retObj.code = RETURN_CODE.WRONG_POST_DATA
        retObj.msg = "post data is not a valid json"
        inputObj = nil
    else
        inputObj = decodedObj
    end

    if inputObj then
        -- validate post data
        if not inputObj.name then
            retObj.code = RETURN_CODE.WRONG_POST_DATA
            retObj.msg = "name field is mandatory"
            inputObj = nil
        end
    end

    if inputObj then
        local ok, roleObj = roleDao.createRole(inputObj)
        if not ok then
            retObj.code = RETURN_CODE.ROLE_CREATE_FAIL
            retObj.msg = roleObj -- second parameter is error msg when error occur 
        else
            retObj.code = RETURN_CODE.SUCCESS
            retObj.msg = "success"
            retObj.data = roleObj
        end
    end

    res:json(retObj, true)
end

local function getRoleById(req, res, next)
    local retObj = {}
    local roleId = tonumber(req.params.id)
    if not roleId then
        retObj.code = RETURN_CODE.ROLE_ID_INVALID
        retObj.msg = "roleId is not valid"
    else
        local ok, roleObj = roleDao.getRoleById(roleId)
        if not ok then
            retObj.code = RETURN_CODE.ROLE_QUERY_FAIL
            retObj.msg = roleObj -- second parameter is error msg when error occur 
        else
            retObj.code = RETURN_CODE.SUCCESS
            retObj.msg = "success"
            retObj.data = roleObj
        end
    end
    res:json(retObj, true)
end

local function getRoleByName(req, res, next)
    local retObj = {}
    local roleName = req.params.name

    local ok, roleObj = roleDao.getRoleByName(roleName)
    if not ok then
        retObj.code = RETURN_CODE.ROLE_QUERY_FAIL
        retObj.msg = roleObj -- second parameter is error msg when error occur 
    else
        retObj.code = RETURN_CODE.SUCCESS
        retObj.msg = "success"
        retObj.data = roleObj
    end

    res:json(retObj, true)
end

local function updateRoleById(req, res, next)
    local retObj = {}
    local roleId = tonumber(req.params.id)
    if not roleId then
        retObj.code = RETURN_CODE.ROLE_ID_INVALID
        retObj.msg = "roleId is not valid"
    else
        local inputObj = nil
        local ok, decodedObj = pcall(cjson.decode, req.body_raw)
        if not ok then
            retObj.code = RETURN_CODE.WRONG_POST_DATA
            retObj.msg = "post data is not a valid json"
            inputObj = nil
        else
            inputObj = decodedObj
            inputObj.id = roleId
        end

        if inputObj then
            local ok, roleObj = roleDao.getRoleById(roleId)
            if not ok then
                retObj.code = RETURN_CODE.ROLE_QUERY_FAIL
                retObj.msg = roleObj -- second parameter is error msg when error occur 
            else
                local ok, msg = roleDao.updateRole(inputObj)
                if not ok then
                    retObj.code = RETURN_CODE.ROLE_QUERY_FAIL
                    retObj.msg = msg
                else
                    retObj.code = RETURN_CODE.SUCCESS
                    retObj.msg = "success"
                end
            end
        end
    end
    res:json(retObj, true)
end

local function deleteRoleById(req, res, next)
    local retObj = {}
    local roleId = tonumber(req.params.id)
    if not roleId then
        retObj.code = RETURN_CODE.ROLE_ID_INVALID
        retObj.msg = "roleId is not valid"
    else
        local ok, roleObj = roleDao.getRoleById(roleId)
        if not ok then
            retObj.code = RETURN_CODE.ROLE_QUERY_FAIL
            retObj.msg = roleObj -- second parameter is error msg when error occur 
        else
            local ok, roleObj = roleDao.deleteRoleById(roleId)
            if not ok then
                retObj.code = RETURN_CODE.ROLE_DELETE_FAIL
                retObj.msg = roleObj -- second parameter is error msg when error occur 
            else
                retObj.code = RETURN_CODE.SUCCESS
                retObj.msg = "success"
            end
        end
    end
    res:json(retObj, true)
end

roleRouter:post("/roles", createRole)
roleRouter:get("/roles/:id", getRoleById)
roleRouter:get("/roles/name/:name", getRoleByName)
roleRouter:put("/roles/:id", updateRoleById)
roleRouter:delete("/roles/:id", deleteRoleById)

return roleRouter
