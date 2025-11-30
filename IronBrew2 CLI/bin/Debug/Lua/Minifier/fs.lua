--- Utility functions for operations on a file system.
--
-- **Note: This module is not part of public API!**
----
local fmt = string.format
local io_open = io.open
local pcall = pcall

local UTF8_BOM = '\239\187\191'

local function normalize_io_error (name, err)
    if err and err:sub(1, #name + 2) == name..': ' then
        err = err:sub(#name + 3)
    end
    return err or 'unknown error'
end

local M = {}

--- Reads the specified file and returns its content as string.
--
-- @tparam string filename Path of the file to read.
-- @tparam string mode The mode in which to open the file, see @{io.open} (default: "r").
-- @treturn[1] string A content of the file.
-- @treturn[2] nil
-- @treturn[2] string An error message.
function M.read_file (filename, mode)
    local handler, err = io_open(filename, mode or 'r')
    if not handler then
        return nil, fmt('Could not open %s for reading: %s',
                        filename, normalize_io_error(filename, err))
    end

    local content, read_err = handler:read('*a')
    pcall(handler.close, handler)
    
    if not content then
        return nil, fmt('Could not read %s: %s', 
                        filename, normalize_io_error(filename, read_err))
    end

    if content:sub(1, #UTF8_BOM) == UTF8_BOM then
        content = content:sub(#UTF8_BOM + 1)
    end

    return content
end

--- Writes the given data to the specified file.
--
-- @tparam string filename Path of the file to write.
-- @tparam string data The data to write.
-- @tparam ?string mode The mode in which to open the file, see @{io.open} (default: "w").
-- @treturn[1] true
-- @treturn[2] nil
-- @treturn[2] string An error message.
function M.write_file (filename, data, mode)
    local handler, err = io_open(filename, mode or 'w')
    if not handler then
        return nil, fmt('Could not open %s for writing: %s',
                        filename, normalize_io_error(filename, err))
    end

    local _, write_err = handler:write(data)
    if write_err then
        pcall(handler.close, handler)
        return nil, fmt('Could not write %s: %s', filename, normalize_io_error(filename, write_err))
    end

    local flush_ok, flush_err = handler:flush()
    if not flush_ok then
        pcall(handler.close, handler)
        return nil, fmt('Could not flush %s: %s', filename, normalize_io_error(filename, flush_err))
    end

    local close_ok, close_err = pcall(handler.close, handler)
    if not close_ok then
        return nil, fmt('File %s written, but could not close: %s', 
                        filename, normalize_io_error(filename, close_err))
    end

    return true
end

return M
