local _M = {}

function _M.fileExists(name)
    local f=io.open(name,"r")
    if f~=nil then io.close(f) return true else return false end
 end

function _M.read_from_file(file_name)
    local f = io.open(file_name, "r")
    if not f then
        return nil
    end
    local string = f:read("*all")
    f:close()
    return string
end

-- Function to write to a file with error handling
function _M.write_to_file(filename, content)
    -- Attempt to open the file for writing
    local file, err = io.open(filename, "w")
    
    if not file then
        return false, err
    end
    
    -- Attempt to write content to the file
    local success, writeErr = file:write(content)
    
    if not success then
        -- Close the file (important to do this even if writing fails)
        file:close()
        return false, writeErr
    end
    
    file:close()
    return true, "success"
end

return _M
