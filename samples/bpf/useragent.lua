local data = require'data'

local blacklist = {
	['curl/7.54.0'] = true,
}

function checkuseragent(pkt)
	local useragent = string.match(tostring(pkt), "User%-Agent:%s(.-)\r\n")

	return blacklist[useragent]
end
