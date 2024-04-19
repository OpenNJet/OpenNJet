local userRouter = require("api_gateway.routes.user")
local groupRouter = require("api_gateway.routes.group")
local roleRouter = require("api_gateway.routes.role")

return function(app)
    app:use("/api_gateway/identities", userRouter())
    app:use("/api_gateway/identities", groupRouter())
    app:use("/api_gateway/identities", roleRouter())
end
