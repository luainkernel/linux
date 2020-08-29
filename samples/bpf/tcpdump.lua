local xdplua  = require'xdplua'
local lunatik = require'lunatik'
local memory  = require'memory'
local session = lunatik.session()
local kscript = [[
	function toip(n)
		local addr = {}
		for i = 0, 3 do
			table.insert(addr, string.format('%d', (n >> (i * 8)) & 0xFF))
		end
		return table.concat(addr, '.')
	end

	function tcpdump(srcip, sport, dstip, dport)
		if dport ~= 22 then
			print(toip(srcip) .. ':' .. sport .. ' -> ' .. toip(dstip) .. ':' .. dport)
		end
	end
]]

local states_list = session:list()

print(#states_list)

for k, v in pairs(states_list) do
	local state = session:getstate(v.name)
	state:dostring(kscript, v.name)
end
