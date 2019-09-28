xdplua = require'xdplua'

function update(map)
	xdplua.bpf_map_update_elem(map, 1, 3)
end
