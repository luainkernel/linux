parse = {}

function parse.mac(pkt)
	local maclen = 14
	local layout = data.layout{dst = { 0, 6 * 8 }, src = { 6 * 8, 6 * 8 },
					type = { 12 * 8, 2 * 8 }}
	local macdata = pkt:layout(layout)
	return macdata.type, maclen
end

function parse.ip(pkt)
	local layout = data.layout{ihl = { 4, 4 }, proto = { 72, 8 }}
	local ipdata = pkt:layout(layout)
	return ipdata.proto, ipdata.ihl * 4
end

function parse.udp(pkt)
	local layout = data.layout{source = { 0, 2 * 8, 'net' },
				destination = { 2 * 8, 2 * 8, 'net' }}
	local udpdata = pkt:layout(layout)
	return udpdata.source, udpdata.destination
end

function parse.dnsquery(pkt)
	local hdrlayout = data.layout{
		flags = { 2 * 8, 2 * 8},
		numqueries = { 4 * 8, 2 * 8 },
		numanswers = { 6 * 8, 2 * 8 },
		numautorities = { 8 * 8, 2 * 8 },
		numadditional = { 10 * 8, 2 * 8 },
	}

	local dnspkt = pkt:layout(hdrlayout)
	local dnsheaderlen = 12

	if dnspkt.numqueries > 1 then return end

	local postdomainoffset, domain = dns.walkdomain(dnspkt, dnsheaderlen, true)
	if not postdomainoffset then
		return
	end

	return dnspkt, domain, postdomainoffset
end
