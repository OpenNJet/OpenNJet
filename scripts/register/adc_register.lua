local cjson=require("cjson")

return function (data)
    --get token via login api
    local login_url = data.login_api
    local post_data={}
    post_data.username=data.username
    post_data.password=data.password

    local httpc = require("resty.http").new()
    local token_res, err = httpc:request_uri(login_url, {
      method = "POST",
      body = cjson.encode(post_data),
      headers = {
        ["Content-Type"]="application/json",
        accept="application/json",
      },
      ssl_verify = false,
    })
    if not token_res then
      njt.log(njt.ERR, "adc return err:" .. err) 
      return {code= 400, msg= "adc login err:".. err}
    end

    local body=token_res.body 
    local ok,respObj=pcall(cjson.decode, body)
    if not ok or not respObj then
      njt.log(njt.ERR, "adc login response body err") 
      return {code= 401, msg= "adc login response body err"}
    end

    if (respObj.res.code == "1115-0000") then
      njt.log(njt.INFO, "adc login success:") 
    else
      njt.log(njt.ERR, "adc login response body err:" .. respObj.res.msg) 
      return {code= 401, msg= "adc login response body err:" .. respObj.res.msg}
    end

    --register
    local adc_token=respObj.data.token
    local register_url=data.pool_register_api
    local register_post_data={}

    register_post_data.weight="10"
    register_post_data.maxconn="0"
    register_post_data.maxreq="0"
    register_post_data.bandwidth="0"
    register_post_data.healthcheck_relation="all"
    register_post_data.elastic_enable="off"
    register_post_data.elastic_virtualmachine=""
    register_post_data.enable="on"
    register_post_data.conn_pool_size="1024"
    register_post_data.pg_priority="0"
    register_post_data.address=data.address

    local register_res, err = httpc:request_uri(register_url, {
      method = "POST",
      body = cjson.encode(register_post_data),
      headers = {
        ["X-Access-token"]=adc_token,
        ["Content-Type"]="application/json",
        accept="application/json",
     },
      ssl_verify = false,
    })

    if not register_res then
      njt.log(njt.ERR, "adc register return err:" .. err) 
      return {code= 402, msg= "adc register return err:".. err}
    end
   
    local register_res_body=register_res.body 
    local ok,registerRespObj=pcall(cjson.decode, register_res_body)
    if not ok or not registerRespObj then
      njt.log(njt.ERR, "adc register return err") 
      return {code= 403, msg= "adc register return err"}
    end

    if registerRespObj.res.code == "1105-0003" then
      njt.log(njt.INFO, "adc register success(exsited)") 
      return {code= 201, msg= "adc register success(exsited):" .. registerRespObj.res.msg}
    end

    if registerRespObj.res.code == "1105-0000" then
      njt.log(njt.INFO, "adc register success") 
      return {code= 200, msg= "adc register success:" .. registerRespObj.res.msg}
    end

    njt.log(njt.INFO, "adc register err" .. registerRespObj.res.msg) 
    return {code= 400, msg= "adc register err:" .. registerRespObj.res.msg}
end