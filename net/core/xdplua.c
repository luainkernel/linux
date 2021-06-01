/* XDPLua internal functions
 * Copyright (C) 2021 Victor Nogueira <victor.nogueira@ring-0.io>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License as
 * published by the Free Software Foundation version 2.
 *
 * This program is distributed "as is" WITHOUT ANY WARRANTY of any
 * kind, whether express or implied; without even the implied warranty
 * of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 */
#include <net/xdplua.h>

#include <lauxlib.h>
#include <lualib.h>
#include <luadata.h>

DEFINE_PER_CPU(struct xdp_lua_work, luaworks);
EXPORT_PER_CPU_SYMBOL(luaworks);

static void per_cpu_xdp_lua_install(struct work_struct *w)
{
	int this_cpu;
	struct xdp_lua_work *lw;

	this_cpu = smp_processor_id();
	lw = container_of(w, struct xdp_lua_work, work);

	local_bh_disable();
	if (luaL_loadbufferx(lw->L, lw->script, lw->script_len, NULL, "t")) {
		pr_err("error loading Lua script: %s\non cpu: %d\n",
			lua_tostring(lw->L, -1), this_cpu);
		lua_pop(lw->L, 1);
		goto enable;
	}

	if (lua_pcall(lw->L, 0, LUA_MULTRET, 0)) {
		pr_err("error running Lua script: %s\non cpu: %d\n",
			lua_tostring(lw->L, -1), this_cpu);
		lua_pop(lw->L, 1);
	}

enable:
	local_bh_enable();
}

int generic_xdp_lua_install_prog(const char *script, size_t script_len)
{
	int i;

	if (!script || script_len == 0)
		return -EINVAL;

	if (script_len > XDP_LUA_MAX_SCRIPT_LEN)
		return -ENAMETOOLONG;

	for_each_possible_cpu(i) {
		struct xdp_lua_work *lw;

		lw = per_cpu_ptr(&luaworks, i);
		memcpy(lw->script, script, script_len);
		lw->script_len = script_len;
		schedule_work_on(i, &lw->work);
	}

	return 0;
}

void xdp_lua_init(void)
{
	struct xdp_lua_work *lw;
	int i, num_needclose = 0;

	for_each_possible_cpu(i) {
		lw = per_cpu_ptr(&luaworks, i);
		lw->L = luaL_newstate();
		WARN_ON(!lw->L);

		if (unlikely(!lw->L)) {
			num_needclose = i;
			break;
		}

		luaL_openlibs(lw->L);
		luaL_requiref(lw->L, "data", luaopen_data, 1);
		lua_pop(lw->L, 1);

		INIT_WORK(&lw->work, per_cpu_xdp_lua_install);
	}

	for(i = 0; i < num_needclose; i++) {
		lw = per_cpu_ptr(&luaworks, i);
		lua_close(lw->L);
		lw->L = NULL;
	}
}
