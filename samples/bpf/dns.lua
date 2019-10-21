dns = {}

function dns.walkdomain(dnspkt, offset, retrieve)
	local maxsizename = 253
	local domainnamelimit = offset + maxsizename
	local ignore = 0xC0
	local isfirst = true
	local lenlayout = data.layout{len = {0, 8}}
	local dnsheaderlen = 12
	local finaldomaincharlen = 1
	local domain

	while offset < domainnamelimit do
		local segment = dnspkt:segment(offset)
		if not segment then
			return nil
		end
		local labeldata = segment:layout(lenlayout)
		if not labeldata then
			return nil
		end

		local labellen = labeldata.len

		if labellen == ignore then
			offset = offset + 1
			break
		end
		if labellen == 0 then
			break
		end
		if retrieve then
			local label = tostring(dnspkt:segment(offset + 1, labellen))
			if (isfirst) then
				domain = label
				isfirst = false
			else
				domain = domain .. '.' .. label
			end
		end

		offset = offset + labellen + 1
	end

	return offset + finaldomaincharlen, domain
end
