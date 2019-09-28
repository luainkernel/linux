xdplua = require'xdplua'

function lookup(map)
	local val = xdplua.bpf_map_lookup_elem(map, 1)
	print('val', val)
end
