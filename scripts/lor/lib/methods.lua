-- get and post methods is guaranteed, the others is still in process
-- but all these methods shoule work at most cases by default
local supported_http_methods = {
    get = true, -- work well
    post = true, -- work well
    head = true, -- no test
    options = true, -- no test
    put = true, -- work well
    patch = true, -- no test
    delete = true, -- work well
    trace = true, -- no test
    all = true -- todo:
}

return supported_http_methods