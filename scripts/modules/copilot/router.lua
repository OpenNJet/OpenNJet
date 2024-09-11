local regsyncRouter = require("copilot.routes.regsync")

local SUPPORTED_COPILOTS={"regsync"}

local function getSupportedCopilot(req, res, next) 
    local retObj={}
    retObj.code=0
    retObj.msg="success"
    retObj.data = SUPPORTED_COPILOTS

    res:json(retObj, false)
end


return function(app)
    app:get("/copilot", getSupportedCopilot)
    app:use("/copilot/regsync", regsyncRouter())
end