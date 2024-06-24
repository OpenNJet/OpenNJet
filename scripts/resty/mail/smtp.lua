local encode_base64 = njt.encode_base64
local njt_socket_tcp = njt.socket.tcp

local CRLF = "\r\n"

local _M = {}

local function receive_response(sock)
  local status
  local lines = {}
  while true do
    local line, receive_err = sock:receive()
    if not line then
      return nil, receive_err
    end

    table.insert(lines, line)
    status = tonumber(string.sub(line, 1, 3))

    -- Response lines where a dash ("-") follows the status code indicate there
    -- are more lines to this response. So keep reading lines until there's no
    -- dash after the status.
    if string.sub(line, 4, 4) ~= "-" then
      break
    end
  end

  return {
    status = status,
    lines = lines,
  }
end

local function send_data(sock, data)
  local bytes, send_err = sock:send(data)
  if not bytes then
    return false, send_err
  end

  return receive_response(sock)
end

local function send_line(sock, line)
  -- Prevent SMTP injections, by ensuring recipients addresses don't contain
  -- line breaks or are so long that they could potentially cause line breaks.
  --
  -- See http://www.mbsd.jp/Whitepaper/smtpi.pdf
  if #line > 2000 then
    return false, "may not exceed 2kB"
  end
  if njt.re.match(line, "[\r\n]", "jo") then
    return false, "may not contain CR or LF line breaks"
  end

  return send_data(sock, { line, CRLF })
end

local function assert_response_status(min_status, max_status, response, err)
  if err then
    return error(err)
  end

  if not response or not response["status"] then
    return error("Unknown SMTP response: " .. table.concat(response["lines"] or {}, "\n"))
  end

  if response["status"] < min_status or response["status"] > max_status then
    return error("SMTP response was not successful: " .. table.concat(response["lines"] or {}, "\n"))
  end
end

local function assert_response_ok(response, err)
  return assert_response_status(200, 299, response, err)
end

local function assert_response_continue(response, err)
  return assert_response_status(300, 399, response, err)
end

local function ehlo(self, sock)
  local options = self.mailer["options"]
  local response, err = send_line(sock, "EHLO " .. options["domain"])
  assert_response_ok(response, err)

  -- Read the extensions from the EHLO response.
  self.extensions = {}
  for index, line in ipairs(response["lines"]) do
    -- Skip the first response line, since it's just the greeting. Further
    -- lines list extensions.
    if index > 1 then
      -- Extract the rest of the line after the status code. Lowercase the
      -- line, so everything is treated case-insensitively.
      local ehlo_line = string.lower(string.sub(line, 5))

      -- Extract the space-delimited keywords from the line.
      local keywords = {}
      for keyword in string.gmatch(ehlo_line, "%S+") do
        table.insert(keywords, keyword)
      end

      local extension = keywords[1]
      local params = {}
      for i = 2,#keywords do
        local param = keywords[i]
        table.insert(params, param)
      end

      self.extensions[extension] = params
    end
  end
end

local function sslhandshake(self)
  local sock = self.sock
  local options = self.mailer["options"]
  local session, err = sock:sslhandshake(nil, options["ssl_host"] or options["host"], options["ssl_verify"] or false)

  if not session then
    return error("sslhandshake error: " .. (err or ""))
  end
end

local function authenticate(self)
  local sock = self.sock
  local options = self.mailer["options"]
  local auth_type = options["auth_type"]
  local username = options["username"]
  local password = options["password"]
  if auth_type == "plain" then
    assert_response_ok(send_line(sock, "AUTH PLAIN " .. encode_base64("\0" .. username .. "\0" .. password)))
  elseif auth_type == "login" then
    assert_response_continue(send_line(sock, "AUTH LOGIN"))
    assert_response_continue(send_line(sock, encode_base64(username)))
    assert_response_ok(send_line(sock, encode_base64(password)))
  else
    return error("unknown auth_type: " .. (auth_type or ""))
  end
end

local function send_message(self, message)
  local options = self.mailer["options"]
  local sock = self.sock

  -- Open connection
  if sock.settimeouts then
    sock:settimeouts(options["timeout_connect"], options["timeout_send"], options["timeout_read"])
  else
    -- Fallback to settimeout for older versions of njt_lua (pre v0.10.7) where
    -- settimeouts isn't available.
    sock:settimeout(options["timeout_connect"])
  end
  local ok, err = sock:connect(options["host"], options["port"])
  if not ok then
    return error("connect failure: " .. err)
  end

  -- If SSL is explicitly enabled (SMTPS), establish a secure connection first.
  if options["ssl"] then
    sslhandshake(self)
  end

  assert_response_ok(receive_response(sock))

  -- EHLO
  ehlo(self, sock)

  -- If STARTTLS is explicitly enabled, or it's detected as supported, then try
  -- to establish a secure connection.
  if (options["starttls"] or self.extensions["starttls"]) and not options["ssl"] then
    assert_response_ok(send_line(sock, "STARTTLS"))
    sslhandshake(self)

    -- Re-send the EHLO, which re-reads the extensions, since they might
    -- differ over the secure connection.
    ehlo(self, sock)
  end

  if options["auth_type"] then
    authenticate(self)
  end

  -- From
  local from = message:get_from_address()
  assert_response_ok(send_line(sock, "MAIL FROM:<" .. from .. ">"))

  -- Recpients (includes all To, Cc, Bcc addresses).
  local recipients = message:get_recipient_addresses()
  for _, address in ipairs(recipients) do
    assert_response_ok(send_line(sock, "RCPT TO:<" .. address .. ">"))
  end

  -- Send the message body along with the data terminator.
  assert_response_continue(send_line(sock, "DATA"))
  local body = message:get_body_list()
  table.insert(body, CRLF)
  table.insert(body, ".")
  table.insert(body, CRLF)
  assert_response_ok(send_data(sock, body))
end

function _M.new(mailer)
  local sock, err = njt_socket_tcp()
  if not sock then
    return nil, err
  end

  return setmetatable({
    mailer = mailer,
    sock = sock,
    extensions = {},
  }, { __index = _M })
end

function _M.send(self, message)
  local sock = self.sock

  -- Try to send the message, catching any errors.
  local send_ok, send_err = pcall(send_message, self, message)

  -- Always try to quit the connection, regardless of whether or not the send
  -- succeeded.
  local quit_ok, quit_err = send_line(sock, "QUIT")

  -- Always close the socket.
  sock:close()

  -- Return any errors that happened.
  if not send_ok then
    return false, send_err
  end
  if not quit_ok then
    return false, quit_err
  end

  return true
end

return _M
