local data = require'data'
rcu = require'rcu'
local xdplua = require'xdplua'

local eth_p_ip = 0x0800
local ipproto_udp = 17

local function checkanswer(pkt, totoff)
	local dnspkt, domain, postdomainoffset = parse.dnsquery(pkt)
	local ipv4type = 1
	local answerlen = 16
	local answerflag = 0x81A0
	local classin = 0x01

	local anlayout = data.layout{
		domain = { 0, 2* 8 },
		type  =  { 2 * 8, 2 * 8},
		class =  { 4 * 8, 2 * 8},
		ttl = { 6 * 8, 4 * 8 },
		infolen = { 10 * 8,  2 * 8 },
		ipv4   = { 12 * 8,  4 * 8 },
	}

	local query = {
		type  = { 0, 2 * 8 },
		class = { 2 * 8, 2 * 8},
	}

	local queryinfo = pkt:segment(postdomainoffset + 1)	

	queryinfo = queryinfo:layout(query)
	local querytype = queryinfo.type

	if querytype ~= ipv4type then
		return xdp.action.pass
	end

	if rcu[domain] then
		dnspkt.flags = answerflag
		dnspkt.numanswers = 1
		dnspkt.numautorities = 0
		dnspkt.numadditional = 0
		local answeroffset = postdomainoffset + 5
		local answer = data.new(answerlen)
		answer = answer:layout(anlayout)

		answer.domain = 0xC00C
		answer.type = ipv4type
		answer.class = classin
		answer.ttl = 3600
		answer.infolen = 4
		answer.ipv4 = rcu[domain]

		xdplua.udp_reply(answer, answeroffset + totoff)

		return xdp.action.tx
	end

	return xdp.action.pass
end

function dnsserver(pkt)
	local mactype, maclen = parse.mac(pkt)
	local udplen = 8
	macpkt = pkt

	if mactype ~= eth_p_ip then
		return xdp.action.pass
	end
	ippkt = pkt:segment(maclen)
	local ip = parse.ip(ippkt)
	if ip.proto ~= ipproto_udp then
		return xdp.action.pass
	end
	udppkt = ippkt:segment(ip.ihl * 4)

	local dnspkt = udppkt:segment(udplen)
	return checkanswer(dnspkt, maclen + iplen + udplen)
end
