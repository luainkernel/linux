local xdplua = require'xdplua'

local eth_p_ip = 0x0800
local ipproto_udp = 17

function forward(pkt)
	local mactype, maclen  = parse.mac(pkt)
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

	local udp = parse.udp(udppkt)
	local ifindex = xdplua.get_ifindex()
	local pktinfo = {
		saddr =  ip.saddr,
		daddr =  ip.daddr,
		sport =  udp.source,
		dport =  udp.destination,
		proto =  ip.proto,
	}

	local sub = xdp.checkentry(pktinfo, ifindex)
	local iptolookup = sub and sub.daddr or ip.daddr
	local newifindex = xdplua.fib_lookup(iptolookup)

	if newifindex and sub then
		if sub.saddr then
			ip.saddr = sub.saddr
		end
		if sub.sport then
			udp.source = sub.sport
		end
		if sub.daddr then
			ip.daddr = sub.daddr
		end
		if sub.dport then
			udp.destination = sub.dport
		end

		xdplua.do_redirect(newifindex)
		return xdp.action.redirect
	end

	return xdp.action.pass
end
