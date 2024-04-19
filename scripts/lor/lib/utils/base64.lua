local njt       = njt
local base64enc = njt.encode_base64
local base64dec = njt.decode_base64

local ENCODE_CHARS = {
    ["+"] = "-",
    ["/"] = "_",
    ["="] = "."
}

local DECODE_CHARS = {
    ["-"] = "+",
    ["_"] = "/",
    ["."] = "="
}

local base64 = {}

function base64.encode(value)
    return (base64enc(value):gsub("[+/=]", ENCODE_CHARS))
end

function base64.decode(value)
    return base64dec((value:gsub("[-_.]", DECODE_CHARS)))
end

return base64
