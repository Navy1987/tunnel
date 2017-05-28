local core = require "silly.core"
local env = require "silly.env"
local socket = require "socket"
local crypt = require "crypt"
local dns = require "dns"
local lz4 = require "lz4"
local key = env.get("crypt")
local packet = require "packet"

local function tunnel_intenet(tunnelfd)
	local pk = packet.read(tunnelfd)
	local port = string.unpack("<I2", pk)
	local domain = pk:sub(2+1)
	print(domain, port)
	if dns.isdomain(domain) then
		domain = assert(dns.query(domain, 10000))
	end
	local addr = string.format("%s@%d", domain, port)
	local fd = socket.connect(addr)
	print("connect", fd, domain, addr)
	core.fork(packet.transfer(tunnelfd, fd))
	core.fork(packet.transfer(fd, tunnelfd))
end

socket.listen(env.get("server"), function(tunnelfd, addr)
        print(tunnelfd, "from", addr)
	socket.limit(fd, 1024 * 1024 * 1024)
	local ok, err = core.pcall(tunnel_intenet, tunnelfd)
	if not ok then
		print(err)
		socket.close(fd)
	end
end)

