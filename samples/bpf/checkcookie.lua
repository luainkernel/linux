--
-- Copyright (C) 2020 ring-0 Ltda
--
-- This program is free software; you can redistribute it and/or
-- modify it under the terms of the GNU General Public License as
-- published by the Free Software Foundation version 2.
--
-- This program is distributed "as is" WITHOUT ANY WARRANTY of any
-- kind, whether express or implied; without even the implied warranty
-- of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
-- GNU General Public License for more details.
--
cookies = {}

local function ip2int(ip)
	local oct1, oct2, oct3, oct4 = ip:match("(%d+)%.(%d+)%.(%d+)%.(%d+)")
	return (oct4 << 24) + (oct3 << 16) + (oct2 << 8) + oct1
end

function loadcookieport(ip, port, cookie)
	local ip = ip2int(ip)

	if not cookies[ip] then
		cookies[ip] = {}
	end

	cookies[ip][port] = cookie
end

function loadcookie(ip, cookie)
	cookies[ip2int(ip)] = cookie
end

function checkcookieport(pkt, ip, port)
	local cookiepkt = tonumber(string.match(tostring(pkt), "Cookie:%s__xdp=(.-)\r\n"))
	if not cookies[ip] then
		return true
	end

	if not cookies[ip][port] then
		return true
	end

	return cookies[ip][port] == cookiepkt and true or false
end

function checkcookie(pkt, ip)
	local cookiepkt = tonumber(string.match(tostring(pkt), "Cookie:%s__xdp=(.-)\r\n"))

	return cookies[ip] == cookiepkt and true or false
end
