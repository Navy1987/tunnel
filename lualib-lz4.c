#include <assert.h>
#include <lua.h>
#include <stdio.h>
#include <lauxlib.h>
#include <lualib.h>
#include <lz4.h>

#define	BUFFSZ	(64 * 1024)
#define	BUFF1	(1)
#define	ALRT	(1)

static char *
resize(lua_State *L, int sz)
{
	void *ptr = lua_newuserdata(L, sz);
	lua_replace(L, lua_upvalueindex(BUFF1));
	return ptr;
}

static int
lcompress(lua_State *L)
{
	int err;
	int dstsz;
	size_t srcsz;
	const char *src = luaL_checklstring(L, 1, &srcsz);
	assert(srcsz);
	char *dst = lua_touserdata(L, lua_upvalueindex(BUFF1));
	dstsz = lua_rawlen(L, lua_upvalueindex(BUFF1));
	for (;;) {
		err = LZ4_compress_fast(src, dst, srcsz, dstsz, ALRT);
		if (err > 0) {
			assert(err <= dstsz);
			break;
		}
		dstsz <<= 1;
		dst = resize(L, dstsz);
	}
	lua_pushlstring(L, dst, err);
	return 1;
}

static int
ldecompress(lua_State *L)
{
	int err;
	int dstsz;
	size_t srcsz;
	int originsz;
	const char *src = luaL_checklstring(L, 1, &srcsz);
	originsz = luaL_checkinteger(L, 2);
	char *dst = lua_touserdata(L, lua_upvalueindex(BUFF1));
	dstsz = lua_rawlen(L, lua_upvalueindex(BUFF1));

	if (dstsz < originsz) {
		dstsz = (originsz + BUFFSZ - 1) / BUFFSZ * BUFFSZ;
		dst = resize(L, dstsz);
	}
	err = LZ4_decompress_fast(src, dst, originsz);
	assert(err > 0);
	lua_pushlstring(L, dst, err);
	return 1;
}


int luaopen_lz4(lua_State *L)
{
        luaL_Reg tbl[] = {
                {"compress", lcompress},
                {"dcompress", ldecompress},
                {NULL, NULL},
        };
	luaL_checkversion(L);
        luaL_newlibtable(L, tbl);
	lua_newuserdata(L, BUFFSZ);
	luaL_setfuncs(L, tbl, 1);

        return 1;
}


