return {
    db_file = njt.config.prefix().."/data/api_gateway.db",
    token_lifetime = 1800, 
    verification_code_lifetime = 120, 
    smtp = {
        host = "127.0.0.1",
        port = 25,
        starttls = false
    },
    email_from = "aa@aa.com",
    ctrl_api_base = "http://127.0.0.1:8081/api/v1"
}