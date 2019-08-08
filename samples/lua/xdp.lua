xdp = {}

xdp.action = {
	abort		= 0,
	drop		= 1,
	pass		= 2,
	tx		= 3,
	redirect	= 4,
}

tables = {}

function xdp.addtotable(newentry)
	local matchsub = {
		match = newentry.match,
		sub = newentry.sub
	}

	local ifindex = newentry.match.ifindex
	newentry.match.ifindex = nil
	if not tables[ifindex] then
		tables[ifindex] = {}
	end

	table.insert(tables[ifindex], matchsub)
end

function xdp.checkentry(pktinfo, ifindex)
	local found
	for _, entry in ipairs(tables[ifindex])  do
		for name, info in pairs(entry.match) do
			if pktinfo[name] ~= info then
				goto continue
			end

		end
		found = entry.sub
		::continue::
	end

	return found
end
