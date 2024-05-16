local lor = require("lor.index")
local app = lor()
local authRouter = require("api_gateway.routes.auth")

app:conf("view enable", false)

app:use("/api_gateway/auth", authRouter())

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
