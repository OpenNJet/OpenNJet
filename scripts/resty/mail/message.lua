local mail_headers = require "resty.mail.headers"
local rfc2822_date = require "resty.mail.rfc2822_date"
local resty_random = require "resty.random"
local str = require "resty.string"

local random_bytes = resty_random.bytes
local encode_base64 = njt.encode_base64
local to_hex = str.to_hex
local match = njt.re.match
local CRLF = "\r\n"

local _M = {}

local function random_tag()
  local num_bytes = 20
  local random = random_bytes(num_bytes, true)
  if not random then
    random = random_bytes(num_bytes, false)
  end

  return math.floor(njt.now()) .. "." .. to_hex(random)
end

local function generate_message_id(mailer)
  local host = mailer.options["domain"]
  return random_tag() .. "@" .. host
end

local function wrapped_base64(value)
  local line_length = 76
  local encoded = encode_base64(value)
  local lines = {}
  local index = 1
  while index <= #encoded do
    local end_index = index + line_length - 1
    local line = string.sub(encoded, index, end_index)
    index = end_index + 1
    table.insert(lines, line)
  end

  return table.concat(lines, CRLF)
end

local function body_insert_header(body, name, value)
  if value then
    table.insert(body, name)
    table.insert(body, ": ")
    table.insert(body, value)
    table.insert(body, CRLF)
  end
end

local function body_insert_boundary(body, boundary)
  table.insert(body, "--")
  table.insert(body, boundary)
  table.insert(body, CRLF)
end

local function body_insert_boundary_final(body, boundary)
  table.insert(body, "--")
  table.insert(body, boundary)
  table.insert(body, "--")
  table.insert(body, CRLF)
  table.insert(body, CRLF)
end

local function body_insert_attachment(body, attachment, mailer)
  assert(attachment["filename"])
  assert(attachment["content_type"])
  assert(attachment["content"])

  local encoded_filename = "=?utf-8?B?" .. encode_base64(attachment["filename"]) .. "?="
  local content_type = attachment["content_type"]
  local disposition = attachment["disposition"] or "attachment"
  local content_id = attachment["content_id"] or generate_message_id(mailer)

  body_insert_header(body, "Content-Type", content_type)
  body_insert_header(body, "Content-Transfer-Encoding", "base64")
  body_insert_header(body, "Content-Disposition", disposition .. '; filename="' .. encoded_filename .. '"')
  body_insert_header(body, "Content-ID", "<" .. content_id .. ">")
  table.insert(body, CRLF)
  table.insert(body, wrapped_base64(attachment["content"]))
  table.insert(body, CRLF)
end

local function extract_address(string)
  local captures, err = match(string, [[<\s*(.+?@.+?)\s*>]], "jo")
  if captures then
    return captures[1]
  else
    if err then
      njt.log(njt.ERR, "lua-resty-mail: regex error: ", err)
    end

    return string
  end
end

local function generate_boundary()
  return "--==_mimepart_" .. random_tag()
end

function _M.new(mailer, data)
  if not data then
    data = {}
  end

  local headers = mail_headers.new()
  if data["headers"] then
    for name, value in pairs(data["headers"]) do
      headers[name] = value
    end
  end

  if data["from"] then
    headers["From"] = data["from"]
  end

  if data["reply_to"] then
    headers["Reply-To"] = data["reply_to"]
  end

  if data["to"] then
    headers["To"] = table.concat(data["to"], ",")
  end

  if data["cc"] then
    headers["Cc"] = table.concat(data["cc"], ",")
  end

  if data["bcc"] then
    headers["Bcc"] = table.concat(data["bcc"], ",")
  end

  if data["subject"] then
    headers["Subject"] = data["subject"]
  end

  if not headers["Message-ID"] then
    headers["Message-ID"] = "<" .. generate_message_id(mailer) .. ">"
  end

  if not headers["Date"] then
    headers["Date"] = rfc2822_date(njt.now())
  end

  if not headers["MIME-Version"] then
    headers["MIME-Version"] = "1.0"
  end

  data["headers"] = headers

  return setmetatable({ mailer = mailer, data = data }, { __index = _M })
end

function _M.get_from_address(self)
  local from
  if self.data["from"] then
    from = extract_address(self.data["from"])
  end

  return from
end

function _M.get_recipient_addresses(self)
  local fields = { "to", "cc", "bcc" }
  local uniq_addresses = {}
  for _, field in ipairs(fields) do
    if self.data[field] then
      for _, string in ipairs(self.data[field]) do
        uniq_addresses[extract_address(string)] = 1
      end
    end
  end

  local list = {}
  for address, _ in pairs(uniq_addresses) do
    table.insert(list, address)
  end

  table.sort(list)

  return list
end

function _M.get_body_list(self)
  local data = self.data
  local headers = data["headers"]
  local body = {}

  local mixed_boundary
  if data["text"] or data["html"] or data["attachments"] then
    mixed_boundary = generate_boundary()
    headers["Content-Type"] = 'multipart/mixed; boundary="' .. mixed_boundary .. '"'
  end

  for name, value in pairs(headers) do
    body_insert_header(body, name, value)
  end

  table.insert(body, CRLF)

  if data["text"] or data["html"] or data["attachments"] then
    table.insert(body, "This is a multi-part message in MIME format.")
    table.insert(body, CRLF)
    body_insert_boundary(body, mixed_boundary)

    local alternative_boundary = generate_boundary()
    body_insert_header(body, "Content-Type", 'multipart/alternative; boundary="' .. alternative_boundary .. '"')
    table.insert(body, CRLF)

    if data["text"] then
      body_insert_boundary(body, alternative_boundary)
      body_insert_header(body, "Content-Type", "text/plain; charset=utf-8")
      body_insert_header(body, "Content-Transfer-Encoding", "base64")
      table.insert(body, CRLF)
      table.insert(body, wrapped_base64(data["text"]))
      table.insert(body, CRLF)
    end

    if data["html"] then
      body_insert_boundary(body, alternative_boundary)
      body_insert_header(body, "Content-Type", "text/html; charset=utf-8")
      body_insert_header(body, "Content-Transfer-Encoding", "base64")
      table.insert(body, CRLF)
      table.insert(body, wrapped_base64(data["html"]))
      table.insert(body, CRLF)
    end

    body_insert_boundary_final(body, alternative_boundary)

    if data["attachments"] then
      for _, attachment in ipairs(data["attachments"]) do
        body_insert_boundary(body, mixed_boundary)
        body_insert_attachment(body, attachment, self.mailer)
      end
    end

    body_insert_boundary_final(body, mixed_boundary)
  end

  return body
end

function _M.get_body_string(self)
  return table.concat(self:get_body_list(), "")
end

return _M
