local data = require'data'
local xdplua = require'xdplua'

local blacklist = {
	['test.com'] = true,
	['test2.com.br'] = true,
}

local function extractsni(pkt)
	local clienthello = 0x01
	local handshake = 0x16
	local servername = 0
	local randlen, handshakelen, compressionlen = 32, 10, 4
	local handshakelayout = data.layout{contenttype = {0, 1 * 8},
						handshaketype = {8 * 5, 8 * 1}}
	local cipherlayout = data.layout{len = {0 * 8, 2 * 8, 'net'}}
	local sessionlayout = data.layout{len = {0 * 8, 1 * 8, 'net'}}
	local exthdrlayout = data.layout{type = {0, 2 * 8}, len = {2 * 8, 2 * 8}}
	local snilayout = data.layout{len = {3 * 8, 2 * 8}}

	local ssldata = pkt:layout(handshakelayout)
	if ssldata.contenttype ~= handshake or
		ssldata.handshaketype ~= clienthello then
		return
	end

	local sslsession = pkt:segment(handshakelen + randlen + 1)
	sslsession:layout(sessionlayout)

	local sslcipher = sslsession:segment(sslsession.len + 1)
	sslcipher:layout(cipherlayout)

	local sslcompression = sslcipher:segment(sslcipher.len + 2)
	sslcompression:layout{exttotlen = {2 * 8, 2 * 8}}

	local extbytes = 0
	local extdata = sslcompression:segment(4)
	while sslcompression.exttotlen >= extbytes do
		if not extdata then return end
		extdata:layout(exthdrlayout)
		if extdata.type == servername then
			extdata = extdata:segment(4)
			extdata:layout(snilayout)
			local sni = extdata:segment(5, extdata.len)
			return tostring(sni)
		end

		extbytes = extbytes + extdata.len
		extdata = extdata:segment(extdata.len + 4)
	end
end

function checksni(pkt, skb)
	if (blacklist[extractsni(pkt)]) then
		xdplua.tcp_rst_reply(skb)
		return true
	end

	return false
end
