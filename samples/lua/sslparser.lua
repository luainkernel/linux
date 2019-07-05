local eth_p_ip = 0x0800
local ipproto_tcp = 6

local xdpaction = {
	abort		= 0,
	drop		= 1,
	pass		= 2,
	tx		= 3,
	rediretct	= 4,
}

local function parsemac(pkt)
	local maclen = 14
	local layout = data.layout{dst = {0, 6*8}, src = {6*8, 6*8}, type = {12*8, 2*8}}
	local macdata = pkt:layout(layout)
	return macdata.type, maclen
end

local function parseip(pkt)
	local layout = data.layout{ihl = {4, 4}, proto = {72, 8}}
	local ipdata = pkt:layout(layout)
	return ipdata.proto, ipdata.ihl * 4
end

local function parsetcp(pkt)
	local layout = data.layout{source = {0, 2*8, 'net'},
		destination = {2*8, 2*8, 'net'}, len = {12 * 8, 1 * 4, 'net'}}
	local tcpdata = pkt:layout(layout)
	return tcpdata.len, tcpdata.destination
end

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

function sslparser(pkt)
	local mactype, maclen = parsemac(pkt)
	if mactype ~= eth_p_ip then
		return xdpaction.pass
	end
	pkt = pkt:segment(maclen)
	local ipproto, iplen = parseip(pkt)
	if ipproto ~= ipproto_tcp then
		return xdpaction.pass
	end
	pkt = pkt:segment(iplen)
	local tcplen, dport = parsetcp(pkt)
	pkt = pkt:segment(tcplen * 4)
	if dport == 443 then
		if pkt then
			local sslsni = extractsni(pkt)
			if sslsni then
				print(sslsni)
			end
		end
	end

	return xdpaction.pass
end
