local data = require'data'
rcu = require'rcu'
local xdplua = require'xdplua'

function checkanswer(pkt, totoff, skb)

	pkt = pkt:segment(totoff)

	local ipv4type = 1
	local answerlen = 16
	local answerflag = 0x81A0
	local classin = 0x01

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
	local dnspkt, domain, postdomainoffset = parse.dnsquery(pkt)

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

	local queryinfo = pkt:segment(postdomainoffset)

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
		local answeroffset = postdomainoffset + 4
		local answer = data.new(answerlen)
		answer = answer:layout(anlayout)

		answer.domain = 0xC00C
		answer.type = ipv4type
		answer.class = classin
		answer.ttl = 3600
		answer.infolen = 4
		answer.ipv4 = rcu[domain]

		return xdplua.udp_reply(answer, answeroffset + totoff, skb)
	end

	return xdp.action.pass
end
