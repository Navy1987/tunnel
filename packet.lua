local core = require "silly.core"
local socket = require "socket"
local pack = string.pack
local unpack = string.unpack

local M = {}

function M.write(fd, dat)
	local len = #dat
	local hdr = string.pack("<I4", len)
	socket.write(fd, hdr .. dat)
end

function M.read(fd)
	local len = socket.read(fd, 4)
	len = string.unpack("<I4", len)
	--print("read", fd, len)
	local dat = socket.read(fd, len)
	return dat
end

function M.fromweb(src, dst)
	return function()
		--print("transfer", src, dst)
		while true do
			local d1 = socket.read(src, 1)
			local d = socket.readall(src)
			if not d or not d1 then
				socket.close(dst)
				return
			end
			d = d1 .. d
			local hdr = pack("<I4I1", #d, 1)
			socket.write(dst, hdr .. d)
		end
	end
end

function M.fromtunnel(src, dst)
	return function()
		while true do
			local d = socket.read(src, 5)
			if not d then
				socket.close(dst)
				return
			end
			local count, v = unpack("<I4I1", d)
			local dat = socket.read(src, count)
			if not dat then
				socket.close(dst)
				return
			end
			if v == 1 then
				socket.write(dst, dat)
			end
		end
	end
end

return M

