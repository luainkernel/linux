--
-- Copyright (C) 2019-2021 Victor Nogueira <victor.nogueira@ring-0.io>
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
xdp = require'xdp'

function update(map)
  xdp.map_update(map, 0, xdp.map_lookup(map, 0) + 1)
end
