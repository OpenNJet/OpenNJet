local mail = require("resty.mail")
local config = require("api_gateway.config.config")

local _M={}

function _M.send(from, to, subject, text)
    local mailer, err = mail.new(config.smtp)
    if err then
        return  false, "mailer library loading error"
    end

    local ok, err = mailer:send({
        from = config.email_from,
        to = {to}, 
        subject = subject,
        text = text
    })
   if not ok then
    return  false, tostring(err)
   end
   return  true, "success"
end

return _M
