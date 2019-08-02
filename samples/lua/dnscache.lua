local data = require'data'
rcu = require'rcu'

local eth_p_ip = 0x0800
local ipproto_udp = 17

local function checkanswer(pkt)
	local answerlen = 10
	local ipv4type = 1
	local dnspkt, domain, postdomainoffset = parse.dnsquery(pkt)

	local anlayout = data.layout{
		type  =  { 0 * 8, 2 * 8},
		class =  { 2 * 8, 2 * 8},
		ttl = { 4 * 8, 4 * 8 },
		infolen = { 8 * 8,  2 * 8 },
		ipv4   = { 10 * 8,  4 * 8 },
	}

	if not dnspkt then
		return xdp.action.pass
	end

	local answeroffset = postdomainoffset + 5

	for i = 1, dnspkt.numanswers do
		answeroffset = dns.walkdomain(dnspkt, answeroffset)
		local segment = dnspkt:segment(answeroffset)
		local answer = segment:layout(anlayout)

		if answer.type == ipv4type then
			local ip = answer.ipv4
			rcu[domain] = ip
		end
		answeroffset = answeroffset + answerlen + answer.infolen
	end
end

function cachedns(pkt)
	local mactype, maclen = parse.mac(pkt)
	local udplen = 8

	if mactype ~= eth_p_ip then
		return xdp.action.pass
	end
	pkt = pkt:segment(maclen)
	local ipproto, iplen = parse.ip(pkt)
	if ipproto ~= ipproto_udp then
		return xdp.action.pass
	end
	pkt = pkt:segment(iplen)

	local sourceport = parse.udp(pkt)
	if sourceport ~= 53 then
		return xdp.action.pass
	end
	
	local dns = pkt:segment(udplen)
	checkanswer(dns)

	return xdp.action.pass
end
