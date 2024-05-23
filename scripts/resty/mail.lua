local message = require "resty.mail.message"
local smtp = require "resty.mail.smtp"

local _M = {
  _VERSION = "1.1.0",
}

function _M.new(options)
  if not options then
    options = {}
  end

  if not options["host"] then
    options["host"] = "localhost"
  end

  if not options["port"] then
    options["port"] = 25
  end

  if not options["domain"] then
    options["domain"] = "localhost.localdomain"
  end

  if options["username"] or options["password"] or options["auth_type"] then
    if not options["username"] then
      return nil, "authentication requested, but missing username"
    end
    if not options["password"] then
      return nil, "authentication requested, but missing password"
    end

    if not options["auth_type"] then
      options["auth_type"] = "plain"
    end

    if options["auth_type"] ~= "plain" and options["auth_type"] ~= "login" then
      return nil, "invalid auth_type: " .. options["auth_type"]
    end
  end

  return setmetatable({ options = options }, { __index = _M })
end

function _M.send(self, data)
  local smtp_conn, smtp_err = smtp.new(self)
  if not smtp_conn then
    return false, smtp_err
  end

  local msg, msg_err = message.new(self, data)
  if not msg then
    return false, msg_err
  end

  return smtp_conn:send(msg)
end

return _M
