local lor = require("lor.index")

local app = lor()

app:conf("view enable", false)

app:get("/app2/pets", function(req, res, next)
    res:send("app2 get pets")
end)
app:get("/app2/pets/:id", function(req, res, next)
    res:send("app2 get pet with id")
end)
app:post("/app2/pets", function(req, res, next)
    res:send("app2 post pets")
end)

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