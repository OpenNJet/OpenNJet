local lor = require("lor.index")
local router = require("api_gateway.router")
local app = lor()

app:conf("view enable", false)

router(app) 

-- 错误处理中间件
app:erroruse(function(err, req, res, next)
    njt.log(njt.ERR, err)

    if req:is_found() ~= true then
        res:status(404):send("404! sorry, not found. ")
    else
        res:status(500):send("internal error")
    end
end)


app:run()
