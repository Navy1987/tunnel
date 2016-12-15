local core = require "silly.core"
local env = require "silly.env"
local socket = require "socket"
local zproto = require "zproto"
local crypt = require "crypt"
local dns = require "dns"
local lz4 = require "lz4"

local proto = zproto:parse [[
connect {
	.type:integer 1
	.addr:string 2
	.port:integer 3
}

]]

local key = env.get("crypt")

local function readpacket(fd)
	local sz = socket.read(fd, 2)
	if not sz then
		return nil
	end
	sz = string.unpack("<I2", sz)
	return socket.read(fd, sz)
end

local function writepacket(fd, d)
	assert(#d < 65536)
	local fmt = string.format("<I2I1c%d", #d)
	local data = string.pack(fmt, #d + 1, 0, d)
	socket.write(fd, data)
end

local function writecompress(fd, sz, d)
	assert(sz < 65536)
	assert(#d < 65536)
	local fmt = string.format("<I2I1I2c%d", #d)
	local data = string.pack(fmt, #d + 3, 1, sz, d)
	socket.write(fd, data)
end

local function pourout(from, to)
	return function()
		while true do
			local body = readpacket(from)
			if not body then
				return
			end
			assert(body)
			--local d = crypt.aesdecode(key, body)
			local d = body
			--print("pourout:", d)
			--print("transfer", #d)
			socket.write(to, d)
		end
	end
end

local function comein(from, to)
	return function()
		while true do
			local d1 = socket.read(from, 1)
			local d2 = socket.readall(from)
			if not (d1 and d2) then
				return
			end
			local d = d1 .. d2
			local p = lz4.compress(d)
			local dlen = #d
			local plen = #p
			if plen < dlen then
				writecompress(to, dlen, p)
			else
				writepacket(to, d)
			end
		end
	end
end

local REQ = {}

REQ[1] = function (fd, req) --IP
	assert(false, "IP support")
end

REQ[2] = function (fd, req) --DOMAIN
	local ip =dns.query(req.addr)
	ip = string.format("%s@%d", ip, req.port)
	local tunnel = socket.connect(ip)
	core.fork(pourout(fd, tunnel))
	core.fork(comein(tunnel, fd))
end

socket.listen(env.get("listen"), function(fd, addr)
        print(fd, "from", addr)
	local body = readpacket(fd)
	local req = proto:decode("connect", body)
	print(req.type, req.addr, req.port)
	assert(REQ[req.type])(fd, req)
end)

