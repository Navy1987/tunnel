local core = require "silly.core"
local env = require "silly.env"
local socket = require "socket"
local zproto = require "zproto"
local crypt = require "crypt"
local dns = require "dns"
local lz4 = require "lz4"

local proto = zproto:parse [[
connect_req {
	#1 --> ip, #2 --> domain
	.type:integer 1
	.addr:string 2
	.port:integer 3
	.handle:integer 4
}

connect_ack {
	.handle:integer 1
	.session:integer 2
}


close {
	.session:integer 1
}

data {
	.session:integer 1
	.data:string 2
}
]]

local key = env.get("crypt")

local protoname = {
	[1] = "connect_req",
	[2] = "close",
	[3] = "data"
}

local REQ = {}
local outtunnel = {}

local function dumptofile(fd, dat)
	local name = fd .. ".dat"
	local f = assert(io.open(name, "a+"))
	f:write(dat)
	f:close()
end

local function cleartunnel(fd)
	for k, v in pairs(outtunnel) do
		if v == fd then
			socket.close(k)
			outtunnel[k] = nil
		end
	end
end

local function dumpstr(str)
	for i = 1, #str do
		print(str:byte(i))
	end
end

local function writepacket(fd, cmd, name, packet)
	local d = proto:encode(name, packet)
	d = crypt.aesencode(key, d)
	local sz = #d + 1
	local fmt = string.format("I4c%dI1", #d)
	local dat = string.pack(fmt, sz, d, cmd)
	--dumpstr(dat)
	assert(socket.write(fd, dat))
	return dat
end

REQ[1] = function (fd, req) --IP
	assert(false, "IP support")
end

local function isip(addr)
	local n = string.match(addr, "[0-9%.]+")
	return n == addr
end

REQ[2] = function (fd, req) --DOMAIN
	local ip
	if isip(req.addr) then
		ip = req.addr
	else
		ip = dns.query(req.addr, 1000)
	end
	ip = string.format("%s@%d", ip, req.port)
	print("connectxx", req.addr, ip)
	local d = socket.connect(ip)
	if not d then
		print("connect fail", ip, req.addr)
		return d
	end
	socket.limit(d, 1024 * 1024 * 1024)
	local ack = {
		handle = req.handle,
		session = d
	}
	writepacket(fd, 1, "connect_ack", ack)
	return d
end

local function reportclose(fd, closefd)
	local ack = {
		session = closefd
	}
	writepacket(fd, 2, "close", ack)
end


local function readpacket(fd)
	local sz = socket.read(fd, 4)
	if not sz then
		return nil
	end
	sz = string.unpack("<I4", sz)
	local d = socket.read(fd, sz)
	if not d then
		return d
	end
	local cmd = d:byte(sz)
	d = crypt.aesdecode(key, d:sub(1, sz - 1))
	local p = protoname[cmd]
	local req = assert(proto:decode(p, d), p)
	req.cmd = cmd
	return req
end

local function comin(out)
	return function()
		local n = 0
		while true do
			local fd = outtunnel[out]
			if not fd then
				return
			end
			local d1 = socket.read(out, 1)
			local d2 = socket.readall(out)
			if not (d1 and d2) then
				print("report close1", out)
				outtunnel[out] = nil
				reportclose(fd, out)
				return
			end
			local ack = {
				session = out,
				data = d1 .. d2
			}
			--print("comin", out, #ack.data)
			local dat = writepacket(fd, 3, "data", ack)
			n = n + #dat
			print("dump out:", out, fd, n)
			--dumptofile(out, dat)
		end
	end
end

socket.listen(env.get("listen"), function(fd, addr)
        print(fd, "from", addr)
	socket.limit(fd, 1024 * 1024 * 1024)
	while true do
		local req = readpacket(fd)
		if not req then
			cleartunnel(fd)
			print("disconnect", fd)
			socket.close(fd)
			return
		end
		--print(req.cmd, req.type)
		if req.cmd == 1 then
			local out = assert(REQ[req.type])(fd, req)
			print("connect", req.type, out)
			if not out then
				print("close tunnel 2", out)
				reportclose(fd, req.handle)
				return
			end
			outtunnel[out] = fd
			core.fork(comin(out))
		elseif req.cmd == 2 then --close
			local out = req.session
			outtunnel[out] = nil
			socket.close(out)
			print("active close", out)
		elseif req.cmd == 3 then --data
			local out = req.session
			print("out", req.session,  #req.data)
			assert(socket.write(out, req.data))
		end
	end
end)

