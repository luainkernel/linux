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
#ifndef __LINUX_NET_XDP_LUA_H__
#define __LINUX_NET_XDP_LUA_H__

#include <lua.h>

#include <linux/skbuff.h>
#include <linux/workqueue.h>
#include <uapi/linux/if_link.h>
#include <linux/filter.h>

struct xdp_lua_work {
	char				script[XDP_LUA_MAX_SCRIPT_LEN];
	size_t				script_len;
	struct lua_State	*L;
	struct sk_buff		*skb;
	struct work_struct	work;
};

DECLARE_PER_CPU(struct xdp_lua_work, luaworks);


#define XDP_LUA_BPF_FUNC(name)	BPF_FUNC_lua_##name

#define xdp_lua_get_skb() 		(this_cpu_ptr(&luaworks)->skb)
#define xdp_lua_set_skb(skb) 	(this_cpu_ptr(&luaworks)->skb = skb)

int generic_xdp_lua_install_prog(const char *script, size_t script_len);
void xdp_lua_init(void);

#define __BPF_LUA_MAP_0(l, m, v, ...) l
#define __BPF_LUA_MAP_1(l, m, v, t, a, ...) l, __BPF_MAP_1(m, v, t, a, __VA_ARGS__)
#define __BPF_LUA_MAP_2(l, m, v, t, a, ...) l, __BPF_MAP_2(m, v, t, a, __VA_ARGS__)
#define __BPF_LUA_MAP_3(l, m, v, t, a, ...) l, __BPF_MAP_3(m, v, t, a, __VA_ARGS__)
#define __BPF_LUA_MAP_4(l, m, v, t, a, ...) l, __BPF_MAP_4(m, v, t, a, __VA_ARGS__)
#define __BPF_LUA_MAP_5(l, m, v, t, a, ...) l, __BPF_MAP_5(m, v, t, a, __VA_ARGS__)

#define __BPF_LUA_MAP(n, l, ...) __BPF_LUA_MAP_##n(l, __VA_ARGS__)

#define LST_TYPE	lua_State
#define LST_NAME	L
#define LST_DECL	__BPF_DECL_ARGS(LST_TYPE*, LST_NAME)

#define BPF_LUA_CALL_x(x, name, ...)					\
	static __always_inline						       \
	u64 ____##name(__BPF_LUA_MAP(x, LST_DECL, __BPF_DECL_ARGS, __BPF_V, __VA_ARGS__)); \
	u64 name(__BPF_REG(x, __BPF_DECL_REGS, __BPF_N, __VA_ARGS__));	       \
	u64 name(__BPF_REG(x, __BPF_DECL_REGS, __BPF_N, __VA_ARGS__))	       \
	{								       \
		int ret = -ENOENT;					\
		lua_State *L = this_cpu_ptr(&luaworks)->L;		\
		WARN_ON(!L);							\
		if (!L)								\
			return ret;						\
		ret = ____##name(__BPF_LUA_MAP(x, LST_NAME, __BPF_CAST, __BPF_N, __VA_ARGS__));	\
		return ret;								\
	}								       \
	static __always_inline						       \
	u64 ____##name(__BPF_LUA_MAP(x, LST_DECL, __BPF_DECL_ARGS, __BPF_V, __VA_ARGS__))

#define BPF_LUA_CALL_0(name, ...)	BPF_LUA_CALL_x(0, name, __VA_ARGS__)
#define BPF_LUA_CALL_1(name, ...)	BPF_LUA_CALL_x(1, name, __VA_ARGS__)
#define BPF_LUA_CALL_2(name, ...)	BPF_LUA_CALL_x(2, name, __VA_ARGS__)
#define BPF_LUA_CALL_3(name, ...)	BPF_LUA_CALL_x(3, name, __VA_ARGS__)
#define BPF_LUA_CALL_4(name, ...)	BPF_LUA_CALL_x(4, name, __VA_ARGS__)
#define BPF_LUA_CALL_5(name, ...)	BPF_LUA_CALL_x(5, name, __VA_ARGS__)

#endif /* __LINUX_NET_XDP_LUA_H__ */
