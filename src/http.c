#include "base64.h"
#include "crypt_sha256.h"
#include <jansson.h>
#include <lauxlib.h>
#include <lua.h>
#include <lualib.h>
#include <microhttpd.h>
#include <mysql.h>
#include <signal.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

struct database
{
    const char *host;
    const char *password;
    const char *database;
    const char *socket;
    const char *user;
    unsigned int port;
};

struct webservice
{
    uint16_t port;
    struct bytecode *bytecode;
};

struct config
{
    struct database database;
    struct webservice webservice;
};

struct upload_data
{
    const char *data;
    size_t size;
};

struct connection_data
{
    char *username;
    char *password;
    const char *method;
    const char *version;
    const char *url;
};

struct context
{
    struct MHD_Connection *connection;
    struct config *config;
    lua_State *lua_main;
    lua_State *lua_thread;
    MYSQL *mysql;
    json_t *json;
    struct upload_data upload_data;
    struct connection_data connection_data;
    int log_ref;
};

static void json_writer
(
    json_t *json,
    int(*writer)(const char *, void *),
    int(*error)(const char *, void *),
    void *cls
)
{
    char *str = json_dumps(json, JSON_ENCODE_ANY | JSON_INDENT(4));
    if(0 == str)
        error("unable to create error string", cls);
    else if(writer(str, cls))
    {
        free(str);
        str = json_dumps(json, JSON_ENCODE_ANY | JSON_INDENT(4));
        if(0 == str)
            error("writer failed and now unable to create error string", cls);
        else
            error(str, cls);
    }
    free(str);
    json_decref(json);
}

static int stderr_writer
(
    const char *msg,
    void *cls
)
{
    fprintf(stderr, msg);
    return 0;
}

#define json_stderr(JSON) json_writer((JSON), stderr_writer, stderr_writer, 0)

static int lua_string_writer
(
    const char *msg,
    void *cls
)
{
    lua_pushstring(cls, msg);
    return 0;
}

static int lerror_(lua_State *, const char *, const char *, int);

#define lerror(LUA, MSG) lerror_((LUA), (MSG), __func__, __LINE__)

static int lua_string_error
(
    const char *msg,
    void *cls
)
{
    lerror(cls, msg);
    return 0;
}

static void push_json_object_to_lua_table(lua_State *, json_t *);
static void push_json_array_to_lua_table(lua_State *, json_t *);

static void json_value_to_lua
(
    lua_State *L,
    json_t *json
)
{
    switch(json_typeof(json))
    {
    case JSON_OBJECT:
        push_json_object_to_lua_table(L, json);
        break;
    case JSON_ARRAY:
        push_json_array_to_lua_table(L, json);
        break;
    case JSON_STRING:
        lua_pushstring(L, json_string_value(json));
        break;
    case JSON_INTEGER:
        lua_pushinteger(L, json_integer_value(json));
        break;
    case JSON_REAL:
        lua_pushnumber(L, json_real_value(json));
        break;
    case JSON_TRUE:
        lua_pushboolean(L, 1);
        break;
    case JSON_FALSE:
        lua_pushboolean(L, 0);
        break;
    case JSON_NULL:
        lua_newtable(L);
        break;
    }
}

static void push_json_array_to_lua_table
(
    lua_State *L,
    json_t *json
)
{
    lua_newtable(L);
    size_t index;
    json_t *value;
    json_array_foreach(json, index, value)
    {
        lua_pushinteger(L, index);
        json_value_to_lua(L, value);
        lua_settable(L, -3);
    }
}

static void push_json_object_to_lua_table
(
    lua_State *L,
    json_t *json
)
{
    lua_newtable(L);
    const char *key;
    json_t *value;
    json_object_foreach(json, key, value)
    {
        lua_pushstring(L, key);
        json_value_to_lua(L, value);
        lua_settable(L, -3);
    }
}

struct json_data
{
    json_t *json;
};

static int get_json_object_string
(
    lua_State *L
)
{
    struct json_data *data = luaL_checkudata(L, 1, "json");
    json_incref(data->json);
    json_writer(data->json, lua_string_writer, lua_string_error, L);
    return 1;
}

static int finalize_json_object
(
    lua_State *L
)
{
    struct json_data *data = luaL_checkudata(L, 1, "json");
    json_decref(data->json);
    return 0;
}

static json_t *wrap_debug_new
(
    json_t *error,
    const char *func,
    int line
)
{
    json_t *json = json_object();
    json_object_set_new(json, "func", json_string(func));
    json_object_set_new(json, "line", json_integer(line));
    json_object_set_new(json, "error", error);
    return json;
}

static json_t *mysql_error_to_json
(
    MYSQL *con
)
{
    json_t *json = json_object();
    json_object_set_new(json, "error", json_string(mysql_error(con)));
    json_object_set_new(json, "errno", json_integer(mysql_errno(con)));
    return json;
}

static void push_json_object
(
    lua_State *L,
    json_t *json
)
{
    struct json_data *data = lua_newuserdata(L, sizeof(struct json_data));
    data->json = json;
    if(luaL_newmetatable(L, "json"))
    {
        lua_pushliteral(L, "__tostring");
        lua_pushcfunction(L, get_json_object_string);
        lua_rawset(L, -3);
        lua_pushliteral(L, "__gc");
        lua_pushcfunction(L, finalize_json_object);
        lua_rawset(L, -3);
    }
    lua_setmetatable(L, -2);
}

static int json_to_lua_error
(
    lua_State *L,
    json_t *json
)
{
    push_json_object(L, json);
    return lua_error(L);
}

static int mysql_lua_error_
(
    lua_State *L,
    MYSQL *con,
    const char *func,
    int line
)
{
    return json_to_lua_error(L, wrap_debug_new(mysql_error_to_json(con), func,
                             line));
}

#define mysql_lua_error(LUA, CON) mysql_lua_error_((LUA), (CON), __func__, __LINE__)

static json_t *json_error_to_json
(
    json_error_t *error
)
{
    json_t *json = json_object();
    json_object_set_new(json, "column", json_integer(error->column));
    json_object_set_new(json, "line", json_integer(error->line));
    json_object_set_new(json, "position", json_integer(error->position));
    json_object_set_new(json, "source", json_string(error->source));
    json_object_set_new(json, "text", json_string(error->text));
    return json;
}

static int json_lua_error_
(
    lua_State *L,
    json_error_t *error,
    const char *func,
    int line
)
{
    return json_to_lua_error(L, wrap_debug_new(json_error_to_json(error), func,
                             line));
}

#define json_lua_error(LUA, ERR) json_lua_error_((LUA), (ERR), __func__, __LINE__)

static void json_print_error_
(
    json_error_t *error,
    const char *func,
    int line
)
{
    json_stderr(wrap_debug_new(json_error_to_json(error), func, line));
}

#define json_print_error(ERR) json_print_error_((ERR), __func__, __LINE__)

static json_t *error_to_json
(
    const char *msg
)
{
    json_t *json = json_object();
    json_object_set_new(json, "message", json_string(msg));
    return json;
}

static int lerror_
(
    lua_State *L,
    const char *msg,
    const char *func,
    int line
)
{
    return json_to_lua_error(L, wrap_debug_new(error_to_json(msg), func, line));
}

static void print_error_
(
    const char *msg,
    const char *func,
    int line
)
{
    json_stderr(wrap_debug_new(error_to_json(msg), func, line));
}

#define print_error(MSG) print_error_((MSG), __func__, __LINE__)

static void log_error_
(
    struct context *context,
    const char *msg,
    const char *func,
    int line
)
{
    json_array_append_new(context->json, wrap_debug_new(error_to_json(msg), func,
                          line));
}

#define log_error(CONTEXT, MSG) log_error_((CONTEXT), (MSG), __func__, __LINE__)

static json_t *lua_error_to_json
(
    lua_State *L,
    int ret
)
{
    json_t *json = json_object();
    struct json_data *data = luaL_testudata(L, -1, "json");
    if(data)
        json_object_set(json, "error", data->json);
    else
    {
        json_object_set_new(json, "error", json_string(luaL_tolstring(L, -1, 0)));
        lua_pop(L, 1);
    }
    lua_pop(L, 1);
    json_object_set_new(json, "error_code", json_integer(ret));
    return json;
}

static void lua_pcall_log_error_
(
    struct context *context,
    lua_State *L,
    int ret,
    const char *func,
    int line
)
{
    json_array_append_new(context->json, wrap_debug_new(lua_error_to_json(L, ret),
                          func, line));
}

#define lua_pcall_log_error(CONTEXT, LUA, RET) lua_pcall_log_error_((CONTEXT), (LUA), (RET), __func__, __LINE__)

static void lua_pcall_print_error_
(
    lua_State *L,
    int ret,
    const char *func,
    int line
)
{
    json_stderr(wrap_debug_new(lua_error_to_json(L, ret), func, line));
}

#define lua_pcall_print_error(LUA, RET) lua_pcall_print_error_((LUA), (RET), __func__, __LINE__)

static int logref_writer
(
    const char *msg,
    void *cls
)
{
    int ret = 0;
    struct context *context = cls;
    if(LUA_NOREF == context->log_ref)
        stderr_writer(msg, cls);
    else
    {
        lua_State *L = context->lua_thread;
        lua_rawgeti(L, LUA_REGISTRYINDEX, context->log_ref);
        lua_pushstring(L, msg);
        ret = lua_pcall(L, 1, 0, 0);
        if(ret)
            lua_pcall_log_error(context, L, ret);
    }
    return ret;
}

static int json_to_lua
(
    lua_State *L
)
{
    json_error_t error;
    json_t *json = json_loads(
                       luaL_checkstring(L, 1),
                       0,
                       &error);
    if(0 == json)
        return json_lua_error(L, &error);
    push_json_object_to_lua_table(L, json);
    json_decref(json);
    return 1;
}

static int lua_table_is_array
(
    lua_State *L
)
{
    int upper = 0;
    int count = 0;
    lua_pushnil(L);
    while(lua_next(L, -2))
    {
        lua_pushvalue(L, -2);
        if(lua_isinteger(L, -1))
        {
            int idx = lua_tointeger(L, -1);
            if(idx <= 0)
            {
                lua_pop(L, 3);
                return 0;
            }
            upper = max(idx, upper);
            ++count;
        }
        else
        {
            lua_pop(L, 3);
            return 0;
        }
        lua_pop(L, 2);
    }
    return upper == count;
}

static json_t *lua_table_to_json_object(lua_State *);
static json_t *lua_array_to_json_array(lua_State *);
static json_t *lua_value_to_json(lua_State *);

static json_t *lua_table_to_array_or_object
(
    lua_State *L
)
{
    if(lua_table_is_array(L))
        return lua_array_to_json_array(L);
    else
        return lua_table_to_json_object(L);
}

static json_t *lua_value_to_json
(
    lua_State *L
)
{
    json_t *value = 0;
    switch(lua_type(L, -1))
    {
    case LUA_TNIL:
        value = json_null();
        break;
    case LUA_TBOOLEAN:
        value = json_boolean(lua_toboolean(L, -1));
        break;
    case LUA_TNUMBER:
        value = json_real(lua_tonumber(L, -1));
        break;
    default:
    case LUA_TLIGHTUSERDATA:
    case LUA_TSTRING:
    case LUA_TFUNCTION:
    case LUA_TUSERDATA:
    case LUA_TTHREAD:
        value = json_string(luaL_tolstring(L, -1, 0));
        lua_pop(L, 1);
        break;
    case LUA_TTABLE:
        value = lua_table_to_array_or_object(L);
        break;
    }
    lua_pop(L, 1);
    return value;
}

static json_t *lua_array_to_json_array
(
    lua_State *L
)
{
    json_t *json = json_array();
    lua_len(L, -1);
    lua_Integer end = lua_tointeger(L, -1);
    lua_pop(L, 1);
    for(lua_Integer i = 1; i <= end; ++i)
    {
        lua_geti(L, -1, i);
        json_array_append_new(json, lua_value_to_json(L));
    }
    return json;
}

static json_t *lua_table_to_json_object
(
    lua_State *L
)
{
    json_t *json = json_object();
    lua_pushnil(L);
    while(lua_next(L, -2))
    {
        json_t *value = lua_value_to_json(L);
        lua_pushvalue(L, -1);
        json_object_set_new(json, luaL_tolstring(L, -1, 0), value);
        lua_pop(L, 2);
    }
    return json;
}

static int lua_to_json
(
    lua_State *L
)
{
    push_json_object(L, lua_value_to_json(L));
    return 1;
}

struct shared_ptr
{
    void *ptr;
    size_t reference_count;
    void(*finalizer)(void *);
};

static struct shared_ptr *make_shared_ptr
(
    void *ptr,
    void(*finalizer)(void *)
)
{
    struct shared_ptr *shared_ptr = malloc(sizeof(struct shared_ptr));
    if(0 == shared_ptr) return 0;
    shared_ptr->ptr = ptr;
    shared_ptr->reference_count = 0;
    shared_ptr->finalizer = finalizer;
    return shared_ptr;
};

static void inc_ref_shared_ptr
(
    struct shared_ptr *ptr
)
{
    ++ptr->reference_count;
}

static void dec_ref_shared_ptr
(
    struct shared_ptr *ptr
)
{
    if(ptr->reference_count)
        --ptr->reference_count;
    else
    {
        ptr->finalizer(ptr->ptr);
        free(ptr);
    }
};

static void finalize_mysql_free_result
(
    void *ptr
)
{
    mysql_free_result(ptr);
}

struct mysql_result
{
    struct shared_ptr *ptr;
    MYSQL_RES *result;
};

struct mysql_row
{
    struct shared_ptr *ptr;
    MYSQL_RES *result;
    MYSQL_ROW row;
};

static int finalize_mysql_row
(
    lua_State *L
)
{
    struct mysql_row *data = luaL_checkudata(L, 1, "mysql_row");
    dec_ref_shared_ptr(data->ptr);
    return 0;
}

static int get_mysql_row_index
(
    lua_State *L
)
{
    struct mysql_row *data = luaL_checkudata(L, 1, "mysql_row");
    switch(lua_type(L, 2))
    {
    case LUA_TSTRING:
    {
        MYSQL_FIELD *field;
        const char *str = lua_tostring(L, 2);
        int index = 0;
        mysql_field_seek(data->result, 0);
        while(field = mysql_fetch_field(data->result))
        {
            if(0 == strcasecmp(field->name, str))
            {
                char *column = data->row[index];
                if(column)
                    lua_pushstring(L, column);
                else
                    lua_newtable(L);
                return 1;
            }
            ++index;
        }
        return 0;
    }
    case LUA_TNUMBER:
        if(!lua_isinteger(L, 2)) return 0;
        int index = lua_tointeger(L, 2);
        if(index < 1 || index > mysql_num_fields(data->result)) return 0;
        char *column = data->row[index - 1];
        if(column)
            lua_pushstring(L, column);
        else
            lua_newtable(L);
        return 1;
    default:
        return 0;
    }
}

static void push_mysql_row
(
    lua_State *L,
    struct mysql_result *result,
    MYSQL_ROW row
)
{
    struct mysql_row *data = lua_newuserdata(L, sizeof(struct mysql_row));
    data->result = result->result;
    data->ptr = result->ptr;
    data->row = row;
    inc_ref_shared_ptr(result->ptr);
    if(luaL_newmetatable(L, "mysql_row"))
    {
        lua_pushliteral(L, "__index");
        lua_pushcfunction(L, get_mysql_row_index);
        lua_rawset(L, -3);
        lua_pushliteral(L, "__gc");
        lua_pushcfunction(L, finalize_mysql_row);
        lua_rawset(L, -3);
    }
    lua_setmetatable(L, -2);
}

static int get_mysql_result_index
(
    lua_State *L
)
{
    struct mysql_result *data = luaL_checkudata(L, 1, "mysql_result");
    if(!lua_isinteger(L, 2)) return 0;
    int index = lua_tointeger(L, 2);
    if(index < 1 || index > mysql_num_rows(data->result)) return 0;
    mysql_data_seek(data->result, index - 1);
    push_mysql_row(L, data, mysql_fetch_row(data->result));
    return 1;
}

static int get_mysql_result_size
(
    lua_State *L
)
{
    struct mysql_result *data = luaL_checkudata(L, 1, "mysql_result");
    lua_pushinteger(L, mysql_num_rows(data->result));
    return 1;
}

static int finalize_mysql_result
(
    lua_State *L
)
{
    struct mysql_result *data = luaL_checkudata(L, 1, "mysql_result");
    dec_ref_shared_ptr(data->ptr);
    return 0;
}

static void push_mysql_result
(
    lua_State *L,
    MYSQL_RES *result
)
{
    struct mysql_result *data = lua_newuserdata(L, sizeof(struct mysql_result));
    data->result = result;
    data->ptr = make_shared_ptr(result, finalize_mysql_free_result);
    if(luaL_newmetatable(L, "mysql_result"))
    {
        lua_pushliteral(L, "__index");
        lua_pushcfunction(L, get_mysql_result_index);
        lua_rawset(L, -3);
        lua_pushliteral(L, "__gc");
        lua_pushcfunction(L, finalize_mysql_result);
        lua_rawset(L, -3);
        lua_pushliteral(L, "__len");
        lua_pushcfunction(L, get_mysql_result_size);
        lua_rawset(L, -3);
    }
    lua_setmetatable(L, -2);
}

struct context_data
{
    struct context *context;
};

static struct context *get_context
(
    lua_State *L
)
{
    return ((struct context_data *)lua_getextraspace(L))->context;
}

static void set_context
(
    lua_State *L,
    struct context *context
)
{
    ((struct context_data *)lua_getextraspace(L))->context = context;
}

static int query
(
    lua_State *L
)
{
    struct context *context = get_context(L);
    if(0 == context->mysql)
    {
        context->mysql = mysql_init(0);
        if(0 == context->mysql)
            return lerror(L, "unable to initialise MYSQL");
        if(0 == mysql_real_connect(context->mysql,
                                   context->config->database.host,
                                   context->config->database.user,
                                   context->config->database.password,
                                   context->config->database.database,
                                   context->config->database.port,
                                   context->config->database.socket,
                                   0))
            return mysql_lua_error(L, context->mysql);
    }
    MYSQL *con = context->mysql;
    if(mysql_query(con, luaL_checkstring(L, 1)))
        return mysql_lua_error(L, con);
    MYSQL_RES *result = mysql_store_result(con);
    if(0 == result)
        return mysql_lua_error(L, con);
    push_mysql_result(L, result);
    return 1;
}

static int yield
(
    lua_State *L
)
{
    return lua_yield(L, 0);
}

static int connection_iter
(
    void *cls,
    enum MHD_ValueKind kind,
    const char *key,
    const char *value
)
{
    lua_State *L = cls;
    lua_pushstring(L, key);
    if(value)
        lua_pushstring(L, value);
    else
        lua_pushliteral(L, "");
    lua_rawset(L, -3);
    return MHD_YES;
}

static int get_connection_value
(
    lua_State *L
)
{
    switch(lua_gettop(L))
    {
    case 0:
        return lerror(L, "must provide a kind and optionally a key");
    case 1:
    {
        int kind = luaL_checkinteger(L, 1);
        lua_newtable(L);
        MHD_get_connection_values(get_context(L)->connection,
                                  kind,
                                  connection_iter,
                                  L);
        return 1;
    }
    default:
    {
        const char *key = 0;
        if(!lua_isnil(L,2))
            key = luaL_checkstring(L, 2);
        const char *value = MHD_lookup_connection_value(
                                get_context(L)->connection,
                                luaL_checkinteger(L, 1),
                                key);
        if(value)
            lua_pushstring(L, value);
        else
            lua_pushnil(L);
        return 1;
    }
    }
}

static int get_upload_data_string
(
    lua_State *L
)
{
    struct context *context = get_context(L);
    struct upload_data *data = &context->upload_data;
    if(0 == data->size) return 0;
    lua_pushlstring(L, data->data, data->size);
    return 1;
}

static int lua_stderr
(
    lua_State *L
)
{
    fprintf(stderr, luaL_tolstring(L, 1, 0));
    return 0;
}

static int get_log
(
    lua_State *L
)
{
    struct context *context = get_context(L);
    if(LUA_NOREF == context->log_ref)
        lua_pushcfunction(L, lua_stderr);
    else
        lua_rawgeti(L, LUA_REGISTRYINDEX, context->log_ref);
    return 1;
}

static int set_log
(
    lua_State *L
)
{
    struct context *context = get_context(L);
    luaL_unref(L, LUA_REGISTRYINDEX, context->log_ref);
    if(lua_isnil(L, -1))
        context->log_ref = LUA_NOREF;
    else
        context->log_ref = luaL_ref(L, LUA_REGISTRYINDEX);
    return 0;
}

static int index_lookup
(
    lua_State *L
)
{
    if(lua_gettable(L, lua_upvalueindex(1)))
    {
        lua_insert(L, -2);
        lua_call(L, 1, 1);
    }
    else
        lua_pushnil(L);
    return 1;
}

static int newindex_lookup
(
    lua_State *L
)
{
    lua_insert(L, -2);
    if(lua_gettable(L, lua_upvalueindex(1)))
    {
        lua_insert(L, -3);
        lua_call(L, 2, 0);
    }
    return 0;
}

struct bytecode
{
    void *data;
    size_t size;
    size_t reserved;
    const char *name;
    struct bytecode *next;
};

static int push_response(lua_State *);

static int crypt
(
    lua_State *L
)
{
    char hash[128];
    if(0 == sha256crypt(luaL_checkstring(L, 1), luaL_checkstring(L, 2), hash))
        return lerror(L, "unable to hash key and salt");
    lua_pushstring(L,hash);
    return 1;
}

static int raw_to_base64
(
    lua_State *L
)
{
    size_t decoded_len  = 0;
    const char *decoded = luaL_checklstring(L, 1, &decoded_len);
    size_t encoded_len = b64e_size(decoded_len) + 1;
    char *encoded = lua_newuserdata(L, encoded_len);
    if(0 == b64_encode((const uint8_t *)decoded, decoded_len,
                       (unsigned char *)encoded))
        return lerror(L, "unable to convert to base64");
    lua_pushlstring(L, encoded, encoded_len-1);
    return 1;
}

static int base64_to_raw
(
    lua_State *L
)
{
    size_t encoded_len = 0;
    const char *encoded = luaL_checklstring(L,1,&encoded_len);
    size_t decoded_len = b64d_size(encoded_len);
    char *decoded = lua_newuserdata(L,decoded_len);
    if(0 == b64_decode((const uint8_t *)encoded,encoded_len,
                       (unsigned char *)decoded))
        return lerror(L, "unable to convert from base64");
    lua_pushlstring(L, decoded, decoded_len);
    return 1;
}

struct pp_data
{
    struct MHD_PostProcessor *pp;
};

static int finalize_pp
(
    lua_State *L
)
{
    struct pp_data *data = luaL_checkudata(L, 1, "post processor");
    if(data->pp)
        MHD_destroy_post_processor(data->pp);
    return 0;
}

static int call_pp
(
    lua_State *L
)
{
    struct pp_data *data = luaL_checkudata(L, 1, "post processor");
    lua_newtable(L);
    size_t len = 0;
    const char *str = luaL_tolstring(L, 2, &len);
    if(MHD_NO == MHD_post_process(data->pp, str, len))
        return lerror(L, "unable to process post data");
    return 1;
}

static int iterator
(
    void *cls,
    enum MHD_ValueKind kind,
    const char *key,
    const char *filename,
    const char *content_type,
    const char *transfer_encoding,
    const char *data,
    uint64_t off,
    size_t size
)
{
    lua_pushstring(L, key);
    lua_pushlstring(L, data, size);
    lua_rawset(L, -3);
    return MHD_YES;
}

static void push_postprocessor
(
    lua_State *L
)
{
    struct pp_data *data = lua_newuserdata(L, sizeof(struct pp_data));
    data->pp = 0;
    if(luaL_newmetatable(L, "post processor"))
    {
        lua_pushliteral(L, "__gc");
        lua_pushcfunction(L, finalize_pp);
        lua_rawset(L, -3);
        lua_pushliteral(L, "__call");
        lua_pushcfunction(L, call_pp);
        lua_rawset(L, -3);
    }
    lua_setmetatable(L, -2);
    struct context *context = get_context(L);
    data->pp = MHD_create_post_processor(context->connection, 65536, iterator, L);
    if(0 == data->pp)
        lerror(L, "unable to create post processor");
    return 1;
}

static int openlib
(
    lua_State *L
)
{
    lua_newtable(L);
    lua_pushliteral(L, "query");
    lua_pushcfunction(L, query);
    lua_rawset(L, -3);
    lua_pushliteral(L, "json_to_lua");
    lua_pushcfunction(L, json_to_lua);
    lua_rawset(L, -3);
    lua_pushliteral(L, "lua_to_json");
    lua_pushcfunction(L, lua_to_json);
    lua_rawset(L, -3);
    struct context *context = get_context(L);
    if(context->connection_data.url)
    {
        lua_pushliteral(L, "url");
        lua_pushstring(L, context->connection_data.url);
        lua_rawset(L, -3);
    }
    if(context->connection_data.method)
    {
        lua_pushliteral(L, "method");
        lua_pushstring(L, context->connection_data.method);
        lua_rawset(L, -3);
    }
    if(context->connection_data.version)
    {
        lua_pushliteral(L, "version");
        lua_pushstring(L, context->connection_data.version);
        lua_rawset(L, -3);
    }
    if(context->connection_data.password)
    {
        lua_pushliteral(L, "password");
        lua_pushstring(L, context->connection_data.password);
        lua_rawset(L, -3);
    }
    if(context->connection_data.username)
    {
        lua_pushliteral(L, "username");
        lua_pushstring(L, context->connection_data.username);
        lua_rawset(L, -3);
    }
    lua_pushliteral(L, "post_processor");
    lua_pushcfunction(L, push_postprocessor);
    lua_rawset(L, -3);
    lua_pushliteral(L, "values");
    lua_pushcfunction(L, get_connection_value);
    lua_rawset(L, -3);
    lua_pushliteral(L, "upload_data");
    lua_pushcfunction(L, get_upload_data_string);
    lua_rawset(L, -3);
    lua_pushliteral(L, "yield");
    lua_pushcfunction(L, yield);
    lua_rawset(L, -3);
    lua_pushliteral(L, "response");
    lua_pushcfunction(L, push_response);
    lua_rawset(L, -3);
    lua_pushliteral(L, "crypt");
    lua_pushcfunction(L, crypt);
    lua_rawset(L, -3);
    lua_pushliteral(L, "base64_to_raw");
    lua_pushcfunction(L, base64_to_raw);
    lua_rawset(L, -3);
    lua_pushliteral(L, "raw_to_base64");
    lua_pushcfunction(L, raw_to_base64);
    lua_rawset(L, -3);
    lua_newtable(L);
    lua_pushliteral(L, "__index");
    lua_newtable(L);
    lua_pushliteral(L, "log");
    lua_pushcfunction(L, get_log);
    lua_rawset(L, -3);
    lua_pushcclosure(L, index_lookup, 1);
    lua_rawset(L, -3);
    lua_pushliteral(L, "__newindex");
    lua_newtable(L);
    lua_pushliteral(L, "log");
    lua_pushcfunction(L, set_log);
    lua_rawset(L, -3);
    lua_pushcclosure(L, newindex_lookup, 1);
    lua_rawset(L, -3);
    lua_setmetatable(L, -2);
    return 1;
}

static int loader
(
    lua_State *L
)
{
    struct bytecode *bytecode = lua_touserdata(L, lua_upvalueindex(1));
    if(luaL_loadbuffer(L,
                       bytecode->data,
                       bytecode->size,
                       bytecode->name))
        lua_error(L);
    lua_insert(L, -3);
    lua_call(L, 2, 1);
    return 1;
}

static void openlibs
(
    struct context *context,
    lua_State *L
)
{
    luaL_openlibs(L);
    lua_getglobal(L, "package");
    lua_getfield(L, -1, "preload");
    lua_pushliteral(L, "jobberws");
    lua_pushcfunction(L, openlib);
    lua_settable(L, -3);
    struct bytecode *bytecode = context->config->webservice.bytecode;
    while(bytecode->next)
    {
        bytecode = bytecode->next;
        lua_pushstring(L, bytecode->name);
        lua_pushlightuserdata(L, bytecode);
        lua_pushcclosure(L, loader, 1);
        lua_settable(L, -3);
    }
    lua_pop(L, 1);
}

static int bytecode_writer
(
    lua_State *L,
    const void *p,
    size_t sz,
    void *ud
)
{
    struct bytecode *bytecode = ud;
    size_t size = bytecode->size + sz;
    if(size > bytecode->reserved)
    {
        size_t reserved = bytecode->reserved * 2;
        void *data = realloc(bytecode->data, reserved);
        if(0 == data)
        {
            print_error("unable to allocate memory for bytecode");
            return 1;
        }
        bytecode->reserved = reserved;
        bytecode->data = data;
    }
    memcpy(bytecode->data + bytecode->size, p, sz);
    bytecode->size = size;
    return 0;
}

static void lua_stack_trace
(
    struct context *context,
    lua_State *L
)
{
    json_t *json = json_object();
    json_array_append_new(context->json, json);
    json_t *arr = json_array();
    json_object_set(json, "stack_trace", arr);
    lua_Debug debug;
    int level = 0;
    while(lua_getstack(L, level, &debug) && lua_getinfo(L, "Sln", &debug))
    {
        json_t *obj = json_object();
        json_array_append_new(arr, obj);
        json_object_set_new(obj, "short_src", json_string(debug.short_src));
        json_object_set_new(obj, "currentline", json_integer(debug.currentline));
        if(debug.name)
            json_object_set_new(obj, "name", json_string(debug.name));
        ++level;
    }
}

static void free_bytecode
(
    struct bytecode *bytecode
)
{
    if(0 == bytecode) return;
    free_bytecode(bytecode->next);
    free(bytecode->data);
    free(bytecode);
}

static struct bytecode *make_bytecode
(
    const char *name,
    const char *filename
)
{
    struct bytecode *bytecode = 0;
    lua_State *L = luaL_newstate();
    if(0 == L)
    {
        print_error("unable to create lua state");
        return 0;
    }
    bytecode = malloc(sizeof(struct bytecode));
    if(0 == bytecode)
    {
        print_error("unable to allocate bytecode");
        goto error;
    }
    bytecode->size = 0;
    bytecode->reserved = 1024;
    bytecode->next = 0;
    bytecode->name = name;
    bytecode->data = malloc(1024);
    if(0 == bytecode->data)
    {
        print_error("unable to allocate bytecode data");
        goto error;
    }
    int ret = luaL_loadfile(L, filename);
    if(ret)
    {
        lua_pcall_print_error(L, ret);
        goto error;
    }
    if(ret = lua_dump(L, bytecode_writer, bytecode, 0))
    {
        lua_pcall_print_error(L, ret);
        goto error;
    }
    lua_close(L);
    return bytecode;
error:
    if(L) lua_close(L);
    free_bytecode(bytecode);
    return 0;
}

static void free_context
(
    struct context *context
)
{
    if(0 == context) return;
    if(context->lua_main)
        lua_close(context->lua_main);
    if(context->mysql)
    {
        mysql_close(context->mysql);
        mysql_thread_end();
    }
    if(context->json) json_decref(context->json);
    if(context->connection_data.username) MHD_free(
            context->connection_data.username);
    if(context->connection_data.password) MHD_free(
            context->connection_data.password);
    free(context);
}

static json_t *connection_data_to_json
(
    struct connection_data *connection_data
)
{
    json_t *json = json_object();
    json_object_set_new(json, "url", json_string(connection_data->url));
    json_object_set_new(json, "method", json_string(connection_data->method));
    json_object_set_new(json, "version", json_string(connection_data->version));
    json_object_set_new(json, "username", json_string(connection_data->username));
    return json;
}

static void request_completed
(
    void *cls,
    struct MHD_Connection *connection,
    void **con_cls,
    enum MHD_RequestTerminationCode toe
)
{
    struct context *context = *con_cls;
    if(0 == context) return;
    if(json_array_size(context->json))
    {
        json_t *json = json_object();
        json_object_set_new(json, "connection",
        connection_data_to_json(&context->connection_data));
        json_object_set_new(json, "termination_code", json_integer(toe));
        json_object_set(json, "log", context->json);
        json_writer(json, logref_writer, stderr_writer, context);
    }
    free_context(context);
    *con_cls = 0;
}

struct response_data
{
    struct MHD_Response *response;
    int status;
    char *realm;
};

static int set_response_status
(
    lua_State *L
)
{
    struct response_data *data = luaL_checkudata(L, 1, "response");
    data->status = luaL_checkinteger(L, 2);
    free(data->realm);
    data->realm = 0;
    return 0;
}

static int set_response_realm
(
    lua_State *L
)
{
    struct response_data *data = luaL_checkudata(L, 1, "response");
    size_t len = 0;
    const char *str = luaL_tolstring(L, 2, &len);
    data->realm = realloc(data->realm, len + 1);
    memcpy(data->realm, str, len + 1);
    data->status = 0;
    return 0;
}

static int set_response
(
    lua_State *L
)
{
    struct response_data *data = luaL_checkudata(L, 1, "response");
    struct MHD_Response *response = 0;
    if(lua_isnil(L, 2))
    {
        response = MHD_create_response_from_buffer(0, "", MHD_RESPMEM_PERSISTENT);
        if(0 == response)
            return lerror(L, "unable to create response");
    }
    else
    {
        size_t len = 0;
        const char *buf = luaL_tolstring(L, 2, &len);
        response = MHD_create_response_from_buffer(
                       len + 1, (void *)buf,
                       MHD_RESPMEM_MUST_COPY);
        if(0 == response)
            return lerror(L, "unable to create response");
    }
    if(data->response)
        MHD_destroy_response(data->response);
    data->response = response;
    return 0;
}

static int send_response
(
    lua_State *L
)
{
    struct response_data *data = luaL_checkudata(L, 1, "response");
    if(data->realm)
    {
        if(0 == data->response)
            data->response = MHD_create_response_from_buffer(0, "", MHD_RESPMEM_PERSISTENT);
        if(0 == data->response)
            return lerror(L, "unable to create response");
        if(MHD_NO == MHD_queue_basic_auth_fail_response(get_context(L)->connection,
                data->realm, data->response))
            return lerror(L, "unable to queue response");
    }
    else
    {
        if(0 == data->response)
        {
            data->response = MHD_create_response_from_buffer(0, "", MHD_RESPMEM_PERSISTENT);
            if(0 == data->response)
                return lerror(L, "unable to create response");
            data->status = MHD_HTTP_NO_CONTENT;
        }
        if(MHD_NO == MHD_queue_response(get_context(L)->connection, data->status,
                                        data->response))
            return lerror(L, "unable to queue response");
    }
    return 0;
}

static int set_response_header
(
    lua_State *L
)
{
    struct response_data *data = luaL_checkudata(L, 1, "response");
    if(0 == data->response)
        return lerror(L, "must first provide a response");
    if(MHD_NO == MHD_add_response_header(data->response, luaL_tolstring(L, 2, 0),
                                         luaL_tolstring(L, 3, 0)))
        return lerror(L, "unable to add response header");
    return 0;
}

static int finalize_response
(
    lua_State *L
)
{
    struct response_data *data = luaL_checkudata(L, 1, "response");
    free(data->realm);
    if(data->response)
        MHD_destroy_response(data->response);
    return 0;
}

static int push_response
(
    lua_State *L
)
{
    struct response_data *data = lua_newuserdata(L, sizeof(struct response_data));
    data->response = 0;
    data->status = 0;
    data->realm = 0;
    if(luaL_newmetatable(L, "response"))
    {
        lua_pushliteral(L, "__newindex");
        lua_newtable(L);
        lua_pushliteral(L, "status");
        lua_pushcfunction(L, set_response_status);
        lua_rawset(L, -3);
        lua_pushliteral(L, "realm");
        lua_pushcfunction(L, set_response_realm);
        lua_rawset(L, -3);
        lua_pushliteral(L, "response");
        lua_pushcfunction(L, set_response);
        lua_rawset(L, -3);
        lua_pushliteral(L, "header");
        lua_pushcfunction(L, set_response_header);
        lua_rawset(L, -3);
        lua_pushcclosure(L, newindex_lookup, 1);
        lua_rawset(L, -3);
        lua_pushliteral(L, "__index");
        lua_newtable(L);
        lua_pushliteral(L, "send");
        lua_pushcfunction(L, send_response);
        lua_rawset(L, -3);
        lua_rawset(L, -3);
        lua_pushliteral(L, "__gc");
        lua_pushcfunction(L, finalize_response);
        lua_rawset(L, -3);
    }
    lua_setmetatable(L, -2);
    return 1;
}

static int send_response_code
(
    struct context *context,
    int code
)
{
    struct MHD_Response *response = MHD_create_response_from_buffer(
                                        0,
                                        "",
                                        MHD_RESPMEM_PERSISTENT);
    if(0 == response)
    {
        log_error(context, "unable to create response");
        return MHD_NO;
    }
    int ret = MHD_queue_response(context->connection, code, response);
    MHD_destroy_response(response);
    return ret;
}

static int answer_to_connection
(
    void *cls,
    struct MHD_Connection *connection,
    const char *url,
    const char *method,
    const char *version,
    const char *upload_data,
    size_t *upload_data_size,
    void **con_cls
)
{
    struct context *context = 0;
    if(0 == *con_cls)
    {
        context = malloc(sizeof(struct context));
        if(0 == context) return MHD_NO;
        *con_cls = context;
        context->connection = connection;
        context->connection_data.url = url;
        context->connection_data.method = method;
        context->connection_data.version = version;
        context->connection_data.password = 0;
        context->connection_data.username = MHD_basic_auth_get_username_password(
                                                connection, &context->connection_data.password);
        context->config = cls;
        context->upload_data.data = 0;
        context->upload_data.size = 0;
        context->mysql = 0;
        context->lua_main = 0;
        context->lua_thread = 0;
        context->log_ref = LUA_NOREF;
        context->json = json_array();
        context->lua_main = luaL_newstate();
        if(0 == context->lua_main)
        {
            log_error(context, "unable to create new lua state");
            return send_response_code(context, MHD_HTTP_INTERNAL_SERVER_ERROR);
        }
        set_context(context->lua_main, context);
        openlibs(context, context->lua_main);
        context->lua_thread = lua_newthread(context->lua_main);
        if(0 == context->lua_thread)
        {
            log_error(context, "unable to create lua thread");
            return send_response_code(context, MHD_HTTP_INTERNAL_SERVER_ERROR);
        }
        struct bytecode *bytecode = context->config->webservice.bytecode;
        int ret = luaL_loadbuffer(context->lua_thread,
                                  bytecode->data,
                                  bytecode->size,
                                  bytecode->name);
        if(ret)
        {
            lua_pcall_log_error(context, context->lua_thread, ret);
            return send_response_code(context, MHD_HTTP_INTERNAL_SERVER_ERROR);
        }
        lua_pushvalue(context->lua_thread, -1);
    }
    else
    {
        context = *con_cls;
        context->upload_data.size = *upload_data_size;
        context->upload_data.data = upload_data;
        *upload_data_size = 0;
    }
    int ret = lua_resume(context->lua_thread, 0, 0);
    switch(ret)
    {
    case LUA_OK:
        lua_pushvalue(context->lua_thread, -1);
    case LUA_YIELD:
        return MHD_YES;
    default:
        lua_pcall_log_error(context, context->lua_thread, ret);
        lua_stack_trace(context, context->lua_thread);
        return send_response_code(context, MHD_HTTP_INTERNAL_SERVER_ERROR);
    }
}

static char *load
(
    const char *filename
)
{
    char *buffer = 0;
    FILE *f = fopen(filename, "rb");
    if(0 == f)
    {
        print_error("unable to open file");
        return 0;
    }
    if(fseek(f, 0, SEEK_END))
    {
        print_error("unable to seek to end of file");
        goto error;
    }
    long length = ftell(f);
    if(length < 0)
    {
        print_error("unable to determine length of file");
        goto error;
    }
    if(fseek(f, 0, SEEK_SET))
    {
        print_error("unable to seek to start of file");
        goto error;
    }
    buffer = malloc(length + 1);
    if(0 == buffer)
    {
        print_error("unable to allocate buffer");
        goto error;
    }
    buffer[length] = '\0';
    if(length != fread(buffer, 1, length, f))
    {
        print_error("unable to read file");
        goto error;
    }
    fclose(f);
    return buffer;
error:
    free(buffer);
    if(f) fclose(f);
    return 0;
}

int main
(
    int argc,
    char **argv
)
{
    if(argc != 2)
    {
        printf("usage: jobberWS config.json\n");
        return EXIT_SUCCESS;
    }
    int ret = EXIT_FAILURE;
    struct config config = {0};
    struct MHD_Daemon *daemon = 0;
    json_t *json = 0;
    struct bytecode *bytecode = 0;
    char *key = 0;
    char *cert = 0;
    if(mysql_library_init(0, 0, 0))
    {
        print_error("unable to initialise mysql library");
        goto error;
    }
    if(0 == mysql_thread_safe())
    {
        print_error("mysql library is not thread safe");
        goto error;
    }
    json_error_t error;
    json = json_load_file(argv[1], 0, &error);
    if(0 == json)
    {
        json_print_error(&error);
        goto error;
    }
    int dport = 0;
    int wport = 0;
    const char *filename;
    json_t *preload = 0;
    const char *key_file = 0;
    const char *cert_file = 0;
    if(json_unpack_ex(json, &error, 0,
                      "{s:{s?s,s:s,s?s,s?s,s:s,s?i},s:{s:i,s:s,s?o,s?{s:s,s:s}}}",
                      "database",
                      "host", &config.database.host,
                      "password", &config.database.password,
                      "database", &config.database.database,
                      "socket", &config.database.socket,
                      "user", &config.database.user,
                      "port", &dport,
                      "webservice",
                      "port", &wport,
                      "filename", &filename,
                      "preload", &preload,
                      "https",
                      "key", &key_file,
                      "cert", &cert_file))
    {
        json_print_error(&error);
        goto error;
    }
    config.database.port = dport;
    config.webservice.port = wport;
    bytecode = make_bytecode(0, filename);
    if(0 == bytecode)
    {
        print_error("unable to create bytecode");
        goto error;
    }
    if(preload)
    {
        if(!json_is_object(preload))
        {
            print_error("preload must be an object");
            goto error;
        }
        struct bytecode *ptr = bytecode;
        const char *key;
        json_t *value;
        json_object_foreach(preload, key, value)
        {
            if(!json_is_string(value))
            {
                print_error("preload values must be strings");
                goto error;
            }
            ptr->next = make_bytecode(key, json_string_value(value));
            if(0 == ptr->next)
            {
                print_error("unable to create bytecode");
                goto error;
            }
            ptr = ptr->next;
        }
    }
    config.webservice.bytecode = bytecode;
    if(key_file)
    {
        key = load(key_file);
        if(0 == key)
        {
            print_error("unable to load key");
            goto error;
        }
    }
    if(cert_file)
    {
        cert = load(cert_file);
        if(0 == cert)
        {
            print_error("unable to load cert");
            goto error;
        }
    }
    if(!key != !cert)
    {
        print_error("https requires both a key and a cert");
        goto error;
    }
    if(key && cert)
    {
        daemon = MHD_start_daemon(MHD_USE_INTERNAL_POLLING_THREAD |
                                  MHD_USE_THREAD_PER_CONNECTION,
                                  config.webservice.port,
                                  0, 0,
                                  answer_to_connection, &config,
                                  MHD_OPTION_NOTIFY_COMPLETED, request_completed, 0,
                                  MHD_OPTION_HTTPS_MEM_KEY, key,
                                  MHD_OPTION_HTTPS_MEM_CERT, cert,
                                  MHD_OPTION_END);
    }
    else
    {
        daemon = MHD_start_daemon(MHD_USE_INTERNAL_POLLING_THREAD |
                                  MHD_USE_THREAD_PER_CONNECTION,
                                  config.webservice.port,
                                  0, 0,
                                  answer_to_connection, &config,
                                  MHD_OPTION_NOTIFY_COMPLETED, request_completed, 0,
                                  MHD_OPTION_END);
    }
    if(0 == daemon)
    {
        print_error("unable to start web server daemon");
        goto error;
    }
    getchar();
    ret = EXIT_SUCCESS;
error:
    if(daemon) MHD_stop_daemon(daemon);
    free_bytecode(bytecode);
    free(key);
    free(cert);
    json_decref(json);
    mysql_library_end();
    return ret;
}
