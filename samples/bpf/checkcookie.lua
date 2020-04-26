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

function checkcookie(pkt, ip, port)
	local cookiepkt = tonumber(string.match(tostring(pkt), "Cookie:%s_xdpcookie=(.-)\r\n"))
	if not cookies[ip] then
		return true
	end

	return cookies[ip] == cookiepkt and true or false
end
