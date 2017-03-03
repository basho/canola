/* -------------------------------------------------------------------
 *
 * Copyright (c) 2013-2017 Basho Technologies, Inc.
 *
 * This file is provided to you under the Apache License,
 * Version 2.0 (the "License"); you may not use this file
 * except in compliance with the License.  You may obtain
 * a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 *
 * -------------------------------------------------------------------
 */

#if (!defined(__STDC_VERSION__) || (__STDC_VERSION__ < 199901L))
#error C99 or higher language support required
#endif

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>

#include <security/pam_appl.h>

#include <erl_nif.h>

typedef struct pam_message  pam_msg_t;
typedef struct pam_response pam_rsp_t;
typedef struct pam_conv     pam_cnv_t;

typedef int (* pam_cnv_f)(int, const pam_msg_t **, pam_rsp_t **, void *);

#define DBG_BUF_SIZE    256
#define DBG_OPEN_MODE   (O_CREAT|O_WRONLY|O_APPEND|O_SYNC)
#define DBG_OPEN_PERM   (S_IRUSR|S_IWUSR|S_IRGRP)

typedef struct
{
    ErlNifEnv *     nif_env;
    char *          secret;
    pam_rsp_t *     pam_rsps;
    unsigned        num_rsps;
}   conv_ctx_t;

static ERL_NIF_TERM ATOM_auth;
static ERL_NIF_TERM ATOM_enomem;
static ERL_NIF_TERM ATOM_error;
static ERL_NIF_TERM ATOM_ok;
static ERL_NIF_TERM ATOM_system;

/*
 * If dbg_switch is non-zero then dbg_sink is a file descriptor opened
 * to always append and flush on every write.
 */
static int  dbg_switch  = 0;
static int  dbg_sink    = -1;

static ERL_NIF_TERM
pam_error_term(
    ErlNifEnv * env, pam_handle_t * pam, int sys, int error, unsigned where)
{
    const char *    desc = pam_strerror(pam, error);
    ERL_NIF_TERM    line = enif_make_uint(env, where);
    ERL_NIF_TERM    text = enif_make_string(env, desc, ERL_NIF_LATIN1);
    ERL_NIF_TERM    type = ATOM_system;
    if (! sys)
    {
        switch (error)
        {
            case PAM_ABORT :
            case PAM_BUF_ERR :
            case PAM_OPEN_ERR :
            case PAM_SERVICE_ERR :
            case PAM_SYSTEM_ERR :
                break;
            default :
                type = ATOM_auth;
                break;
        }
    }
    return  enif_make_tuple2(env, ATOM_error,
                enif_make_tuple3(env, type, text, line));
}
#define nif_pam_error(env, pam, sys, err) \
    pam_error_term(env, pam, sys, err, __LINE__)

#ifdef HAVE_PAM_FAIL_DELAY
static void
no_fail_delay(int ret, unsigned usec, void * ptr)
{
    if (dbg_switch)
    {
        char    dbg[DBG_BUF_SIZE];
        int     len = fprintf(dbg,
            "%u:\tno_fail_delay(%d, %u, %p)\n", __LINE__, ret, usec, ptr);
        if (len > 0)
            write(dbg_sink, dbg, len);
    }
}
#endif  /* HAVE_PAM_FAIL_DELAY */

/*
 * PAM callback to obtain authentication evidence.
 *
 * In our case, the evidence (password) is already in the context.
 */
static int
authen_callback(
    int nmsg, const pam_msg_t ** msgs, pam_rsp_t ** rsps, conv_ctx_t * ctx)
{
    char        dbg[DBG_BUF_SIZE];
    unsigned    idx, cnt;
    int         len;

    if (dbg_switch)
    {
        len = sprintf(dbg,
            "%u:\tauthen_callback(%d, ...)\n", __LINE__, nmsg);
        if (len > 0)
            write(dbg_sink, dbg, len);
    }
    if (nmsg < 1 || nmsg >= PAM_MAX_NUM_MSG)
        return  PAM_CONV_ERR;

    cnt = (unsigned) nmsg;
    /* PAM will call free() on this */
    ctx->pam_rsps = calloc(cnt, sizeof(pam_rsp_t));
    if (ctx->pam_rsps == NULL)
        return  PAM_BUF_ERR;

    ctx->num_rsps = cnt;
    *rsps = ctx->pam_rsps;

    if (dbg_switch)
    {
        for (idx = 0; idx < cnt; ++idx)
        {
            char            nbuf[16];
            const char *    style;

            switch (msgs[idx]->msg_style)
            {
                case PAM_PROMPT_ECHO_OFF :
                    style = "PAM_PROMPT_ECHO_OFF";
                    /* PAM will call free() on this */
                    rsps[idx]->resp = strdup(ctx->secret);
                    break;
                case PAM_PROMPT_ECHO_ON :
                    style = "PAM_PROMPT_ECHO_ON";
                    break;
                case PAM_ERROR_MSG :
                    style = "PAM_ERROR_MSG";
                    break;
                case PAM_TEXT_INFO :
                    style = "PAM_TEXT_INFO";
                    break;
                default :
                    sprintf(nbuf, "%d", msgs[idx]->msg_style);
                    style = nbuf;
                    break;
            }
            len = sprintf(dbg,
                "%u:\tmsgs[%u] %s \"%s\"\n", __LINE__, idx, style, msgs[idx]->msg);
            if (len > 0)
                write(dbg_sink, dbg, len);
        }
    }
    else
        for (idx = 0; idx < cnt; ++idx)
            if (msgs[idx]->msg_style == PAM_PROMPT_ECHO_OFF)
                /* PAM will call free() on this */
                rsps[idx]->resp = strdup(ctx->secret);

    return  PAM_SUCCESS;
}

#define AUTH_SERVICE    0
#define AUTH_USER       1
#define AUTH_SECRET     2
#define AUTH_ARITY      3
/*
 * nif_auth(
 *  Service  :: binary(),
 *  Username :: binary(),
 *  Password :: binary())
 *  -> ok | {error, {auth | system, Reason, Where}}
 */
static ERL_NIF_TERM
nif_auth(ErlNifEnv * env, int argc, const ERL_NIF_TERM argv[])
{
    conv_ctx_t      ctx[1];
    pam_cnv_t       cnv[1];
    ErlNifBinary    bin[AUTH_ARITY];
    char *          str[AUTH_ARITY];
    char *          strbuf;
    pam_handle_t *  pam;
    ERL_NIF_TERM    result;
    unsigned        bufsiz;
    unsigned        idx, pos;
    int             flags, ret;

    if (argc != AUTH_ARITY)
        return  enif_make_badarg(env);

    for (idx = 0; idx < AUTH_ARITY; ++idx)
        if (enif_inspect_binary(env, argv[idx], (bin + idx)) == 0)
            return  enif_make_badarg(env);

    bufsiz = 0;
    for (idx = 0; idx < AUTH_ARITY; ++idx)
        bufsiz += (bin[idx].size + 1);

    if ((strbuf = enif_alloc(bufsiz)) == NULL)
        return  enif_make_tuple2(env, ATOM_error, ATOM_enomem);

    pos = 0;
    for (idx = 0; idx < AUTH_ARITY; ++idx)
    {
        str[idx] = memcpy((strbuf + pos), bin[idx].data, bin[idx].size);
        pos += bin[idx].size;
        strbuf[pos++] = '\0';
    }
    if (dbg_switch)
    {
        char    dbg[DBG_BUF_SIZE * 2];
        char    pw[DBG_BUF_SIZE];
        int     len;

        idx = strlen(str[AUTH_SECRET]);
        memset(pw, '*', idx);
        pw[idx] = '\0';
        len = sprintf(dbg, "%u:\tnif_auth(\"%s\", \"%s\", %s)\n",
            __LINE__, str[AUTH_SERVICE], str[AUTH_USER], pw);
        if (len > 0)
            write(dbg_sink, dbg, len);
    }
    memset(ctx, 0, sizeof(ctx));
    memset(cnv, 0, sizeof(cnv));
    ctx->nif_env = env;
    ctx->secret = str[AUTH_SECRET];
    cnv->conv = (pam_cnv_f) authen_callback;
    cnv->appdata_ptr = ctx;

    pam = NULL;
    flags = dbg_switch ? 0 : PAM_SILENT;

    ret = pam_start(str[AUTH_SERVICE], str[AUTH_USER], cnv, & pam);
    if (ret != PAM_SUCCESS)
    {
        result = nif_pam_error(env, pam, 1, ret);
        goto nopam;
    }
#ifdef HAVE_PAM_FAIL_DELAY
    ret = pam_set_item(pam, PAM_FAIL_DELAY, no_fail_delay);
#endif
    ret = pam_authenticate(pam, flags);
    if (ret != PAM_SUCCESS)
    {
        result = nif_pam_error(env, pam, 0, ret);
        goto done;
    }
    ret = pam_acct_mgmt(pam, flags);
    if (ret != PAM_SUCCESS)
    {
        result = nif_pam_error(env, pam, 0, ret);
        goto done;
    }

    result = ATOM_ok;
done:
    ret = pam_end(pam, ret);
    pam = NULL;
    if (ret != PAM_SUCCESS)
        result = nif_pam_error(env, pam, 1, ret);
nopam:
    memset(strbuf, 0, bufsiz);
    enif_free(strbuf);

    return  result;
}

static int
nif_load(ErlNifEnv * env, void ** priv, ERL_NIF_TERM options)
{
    char            path[FILENAME_MAX];
    char            dbg[DBG_BUF_SIZE + sizeof(path)];
    char            atom_debug[8];
    char            atom_file[8];
    ERL_NIF_TERM    head, tail;
    int             len, debug;

    /* on entry, dbg_switch *should* always be zero */
    if (dbg_switch)
    {
        int fd = dbg_sink;
        dbg_switch = 0;
        dbg_sink = -1;

        len = sprintf(dbg, "%u:\tnif_load(%p, %p)\n", __LINE__, env, *priv);
        if (len > 0)
            write(fd, dbg, len);
        close(fd);
    }
    if (! enif_is_list(env, options))
        return  -1;

    debug = 0;
    tail = options;
    while (enif_get_list_cell(env, tail, & head, & tail))
    {
        if (enif_is_tuple(env, head))
        {
            const ERL_NIF_TERM *    terms;
            int                     arity;
            enif_get_tuple(env, head, & arity, & terms);
            if (arity == 2
                && enif_get_atom(env, terms[0],
                    atom_debug, sizeof(atom_debug), ERL_NIF_LATIN1)
                && strcmp(atom_debug, "debug") == 0
                && enif_is_tuple(env, terms[1]) )
            {
                enif_get_tuple(env, terms[1], & arity, & terms);
                if (arity == 2
                    && enif_get_atom(env, terms[0],
                        atom_file, sizeof(atom_file), ERL_NIF_LATIN1)
                    && strcmp(atom_file, "file") == 0
                    && enif_is_list(env, terms[1]) )
                {
                    len = enif_get_string(
                        env, terms[1], path, sizeof(path), ERL_NIF_LATIN1);
                    if (len > 0)
                    {
                        debug = 1;
                        break;
                    }
                }
            }
        }
    }
    if (debug)
    {
        if ((dbg_sink = open(path, DBG_OPEN_MODE, DBG_OPEN_PERM)) < 0)
            return  errno;

        dbg_switch = 1;

        len = sprintf(dbg,
            "%u:\tnif_load(%p, %p, [{%s, {%s, \"%s\"}}])\n",
            __LINE__, env, *priv, atom_debug, atom_file, path);
        if (len > 0)
            write(dbg_sink, dbg, len);
    }

    /* on upgrade, we want to re-initialize these */
    ATOM_auth   = enif_make_atom(env, "auth");
    ATOM_enomem = enif_make_atom(env, "enomem");
    ATOM_error  = enif_make_atom(env, "error");
    ATOM_ok     = enif_make_atom(env, "ok");
    ATOM_system = enif_make_atom(env, "system");

    return  0;
}

static int
nif_upgrade(ErlNifEnv * env, void ** priv, void ** old, ERL_NIF_TERM options)
{
    if (dbg_switch)
    {
        char    dbg[DBG_BUF_SIZE];
        int     fd, len;

        dbg_switch = 0;
        fd = dbg_sink;
        dbg_sink = -1;

        len = sprintf(dbg,
            "%u:\tnif_upgrade(%p, %p, %p)\n", __LINE__, env, *priv, *old);
        if (len > 0)
            write(fd, dbg, len);
        close(fd);
    }
    return  nif_load(env, priv, options);
}

static void nif_unload(ErlNifEnv * env, void * priv)
{
    if (dbg_switch)
    {
        char    dbg[DBG_BUF_SIZE];
        int     fd, len;

        dbg_switch = 0;
        fd = dbg_sink;
        dbg_sink = -1;

        len = sprintf(dbg, "%u:\tnif_unload(%p, %p)\n", __LINE__, env, priv);
        if (len > 0)
            write(fd, dbg, len);
        close(fd);
    }
}

static ErlNifFunc nif_func[] = {{"auth", AUTH_ARITY, nif_auth}};

ERL_NIF_INIT(canola, nif_func, nif_load, NULL, nif_upgrade, nif_unload)
