local data = require'data'
rcu = require'rcu'

function cachedns(pkt)
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

	local answeroffset = postdomainoffset + 4

	for i = 1, dnspkt.numanswers do
		answeroffset = dns.walkdomain(dnspkt, answeroffset)
		if not answeroffset then
			return
		end

		local segment = dnspkt:segment(answeroffset)
		local answer = segment:layout(anlayout)

		if answer.type == ipv4type then
			local ip = answer.ipv4
			rcu[domain] = ip
		end
		answeroffset = answeroffset + answerlen + answer.infolen
	end
end
