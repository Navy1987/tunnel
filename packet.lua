local core = require "sys.core"
local socket = require "sys.socket"
local crypt = require "sys.crypt"
local key = assert(core.envget("crypt"), "crypt key")
local pack = string.pack
local unpack = string.unpack
local sub = string.sub
local format = string.format
local MTU = 1400
local M = {}

function M.write(fd, dat)
	local len = #dat
	local hdr = string.pack("<I4", len)
	socket.write(fd, hdr .. dat)
end

function M.read(fd)
	local len = socket.read(fd, 4)
	if not len then
		return
	end
	len = string.unpack("<I4", len)
	--print("read", fd, len)
	local dat = socket.read(fd, len)
	return dat
end

local keyword = "社会主义现代化"
while #keyword < MTU do
	keyword = keyword .. keyword
end

local mtu_head = pack("<I4", MTU)
local header_len = {}
setmetatable(header_len, { __mode="kv", __index = function(tbl, len)
	local k = pack("<I4", len)
	header_len[len] = k
	return k
end})

local packet_len = {}
setmetatable(packet_len, { __mode="kv", __index = function(tbl, len)
	local k = format("<c%s", len)
	packet_len[k] = k
	return k
end})


function M.fromweb(src, dst)
	return function()
		local fmt = format("<c%d", MTU)
		--print("transfer", src, dst)
		while true do
			local d = socket.readall(src)
			if not d then
				socket.close(dst)
				return
			end
			if d == "" then
				d = socket.read(src, 1)
				local d1 = socket.readall(src)
				if not d or not d1 then
					socket.close(dst)
					return
				end
				if d1 ~= "" then
					d = d .. d1
				end
			end
			local index = 1
			local len = #d
			while len > MTU do
				local one = unpack(fmt, d, index)
				local dat = mtu_head .. one
				assert(#dat == (MTU+4))
				socket.write(dst, crypt.aesencode(key, dat))
				index = index + MTU
				len = len - MTU
			end
			if len > 0 then
				d = sub(d, index)
				local len = #d
				local head = header_len[len]
				d = head .. d .. sub(keyword, 1, MTU - len)
				d = crypt.aesencode(key, d)
				assert(#d == (MTU+4))
				socket.write(dst, d)
			end
		end
	end
end

function M.fromtunnel(src, dst)
	return function()
		local ONCE =  MTU + 4
		while true do
			local d = socket.read(src, ONCE)
			if not d then
				socket.close(dst)
				return
			end
			d = crypt.aesdecode(key, d)
			local count = unpack("<I4", d)
			local fmt = packet_len[count]
			local dat = unpack(fmt, d, 5)
			socket.write(dst, dat)
		end
	end
end

return M

