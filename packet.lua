
local socket = require "socket"
local M = {}

function M.write(fd, dat)
	local len = #dat
	local hdr = string.pack("<I4", len)
	socket.write(fd, hdr .. dat)
end

function M.read(fd)
	local len = socket.read(fd, 4)
	len = string.unpack("<I4", len)
	print("read", fd, len)
	local dat = socket.read(fd, len)
	return dat
end

function M.transfer(src, dst)
	return function()
		print("transfer", src, dst)
		while true do
			local d = socket.read(src, 1)
			local all = socket.readall(src)
			if not d or not all then
				socket.close(dst)
				return
			end
			socket.write(dst, d .. all)
		end
	end
end

return M

