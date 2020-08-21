local xdplua = require'xdplua'
local lunatik = require'lunatik'
local session = lunatik.session()
local kscript = [[
	function toip(n)
		local addr = {}
		for i = 0, 3 do
			table.insert(addr, string.format('%d', (n >> (i * 8)) & 0xFF))
		end
		return table.concat(addr, '.')
	end

	function icmp(ip, port)
		if port ~= 64 then
			print(toip(ip) .. ':' .. port)
		end
	end
]]

xdplua.detach('enp0s3')
xdplua.attach_ebpf('enp0s3', '../../xdplua_matheus_kern.o')

local state_name = 'CPU '

for i = 0, 3 do
	local xdp = session:getstate(state_name .. i)
	if xdp then
		print('Encontrei o estado: ' .. state_name .. i)
		xdp:dostring(kscript, state_name .. i)
	end
end

