local core = require "sys.core"
local socket = require "sys.socket"
local dns = require "sys.dns"
local crypt = require "sys.crypt"
local packet = require "packet"

local key = core.envget("crypt")

local function tunnel_intenet(tunnelfd)
	local pk = packet.read(tunnelfd)
	local port = string.unpack("<I2", pk)
	local domain = pk:sub(2+1)
	domain = crypt.aesdecode(key, domain)
	--print(domain, port)
	if dns.isdomain(domain) then
		domain = assert(dns.query(domain, 10000), domain)
	end
	local addr = string.format("%s:%d", domain, port)
	local fd = socket.connect(addr)
	--print("connect", fd, domain, addr)
	core.fork(packet.fromtunnel(tunnelfd, fd))
	core.fork(packet.fromweb(fd, tunnelfd))
end

socket.listen(core.envget("server"), function(tunnelfd, addr)
        print(tunnelfd, "from", addr)
	socket.limit(fd, 1024 * 1024 * 1024)
	local ok, err = core.pcall(tunnel_intenet, tunnelfd)
	if not ok then
		print(err)
		socket.close(fd)
	end
end)

