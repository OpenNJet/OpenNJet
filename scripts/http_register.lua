local adc=require("register.adc_register")
local cjson=require("cjson")

njt.req.read_body()
local b=njt.req.get_body_data()
-- njt.log(njt.INFO,b)
local data=cjson.decode(b)
if data.type == "adc" or data.type == "ADC" then
  local r= adc(data)
  njt.say (cjson.encode(r))
else
  njt.log(njt.INFO, "invalid type:".. data.type)
  njt.say (cjson.encode({code= 100, msg= "invalid type:".. data.type}))
end
