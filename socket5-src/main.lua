local core = require "sys.core"
local socket = require "sys.socket"
local crypt = require "sys.crypt"
local packet = require "packet"
local key = assert(core.envget("crypt"), "crypt key")
local serveraddr  = assert(core.envget("server"), "server")
local function auth(fd)
	print("auth start")
	local str = socket.read(fd, 3)
	local ver, nr, method = string.unpack("<I1I1I1", str)
	print(ver, nr, method)
	assert(ver == 0x05)
	local noauth = false
	if method == 0x0 then
		noauth = true
	elseif nr > 1 then
		nr = nr - 1
		str = socket.read(fd, nr)
		for i = 1, str do
			if str:byte(i) == 0x0 then
				noauth = true
			end
		end
	end
	assert(noauth, "not support auth")
	local ack = string.pack("<I1I1", 0x05, 0x00)
	socket.write(fd, ack)
	print("auth ok")
end

local function connect(fd)
	local str = socket.read(fd, 4)
	local ver, req, rev, addr = string.unpack("<I1I1I1I1", str)
	print("connect", ver, req, rev, addr)
	assert(addr == 3, "only support domain")
	--domain len
	str = socket.read(fd, 1)
	local len = str:byte(1)
	--domain name
	local domain = socket.read(fd, len)
	print("connect domain", domain)
	domain = crypt.aesencode(key, domain)
	str = socket.read(fd, 2)
	local port = string.unpack(">I2", str)
	print("connect port", port)
	local tunnelfd = socket.connect(serveraddr)
	print("connect server fd", serveraddr, tunnelfd)
	local hdr = string.pack("<I2", port)
	packet.write(tunnelfd, hdr .. domain)
	core.fork(packet.fromweb(fd, tunnelfd))
	core.fork(packet.fromtunnel(tunnelfd, fd))
	local ack = "\x05\x00\x00\x01\x00\x00\x00\x00\xe9\xc7"
	socket.write(fd, ack)
end

local function socket5(fd)
	auth(fd)
	connect(fd)
end


socket.listen(core.envget("socket5"), function(fd, addr)
	print(fd, "from", addr)
	local ok, err = core.pcall(socket5, fd)
	if not ok then
		print(err)
		socket.close(fd)
	end
end)

