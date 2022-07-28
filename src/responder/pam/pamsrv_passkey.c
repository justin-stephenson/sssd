/*
   SSSD

   PAM Responder - passkey related requests

   Copyright (C) Justin Stephenson <jstephen@redhat.com> 2022

   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 3 of the License, or
   (at your option) any later version.

   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

#include <time.h>

#include "util/util.h"
#include "providers/data_provider.h"
#include "util/child_common.h"
#include "util/strtonum.h"
#include "responder/pam/pamsrv.h"
#include "responder/pam/pam_helpers.h"
#include "lib/certmap/sss_certmap.h"
#include "util/crypto/sss_crypto.h"
#include "util/sss_chain_id.h"
#include "db/sysdb.h"

#define USER_VERIFICATION "user_verification="
#define USER_VERIFICATION_LEN (sizeof(USER_VERIFICATION) -1)

struct passkey_auth_data {
    char *key;
    char *name;
};

enum user_verification {
    ON,
    OFF,
    UNSET
};

struct pam_passkey_auth_send_state {
    struct pam_data *pd;
    struct tevent_context *ev;
    struct sss_child_ctx_old *child_ctx;
    struct child_io_fds *io;
    const char *logfile;
    const char **extra_args;
    char *verify_opts;
    int timeout;
    struct passkey_auth_data *passkey_data;
};

errno_t parse_passkey_verify_opts(TALLOC_CTX *mem_ctx,
                                const char *verify_opts,
                                enum user_verification *_user_verification);

static errno_t passkey_child_exec(struct tevent_req *req);
static void pam_passkey_auth_done(int child_status,
                                struct tevent_signal *sige,
                                void *pvt);

static errno_t get_passkey_child_write_buffer(TALLOC_CTX *mem_ctx,
                                              struct pam_data *pd,
                                              uint8_t **_buf, size_t *_len)
{
    int ret;
    uint8_t *buf;
    size_t len;
    const char *pin = NULL;

    if (pd == NULL || pd->authtok == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Missing authtok.\n");
        return EINVAL;
    }

    switch (sss_authtok_get_type(pd->authtok)) {
    case SSS_AUTHTOK_TYPE_PASSKEY:
        ret = sss_authtok_get_passkey_pin(pd->authtok, &pin, &len);
        if (ret != EOK) {
            DEBUG(SSSDBG_OP_FAILURE, "sss_authtok_get_sc_pin failed.\n");
            return ret;
        }
        if (pin == NULL || len == 0) {
            DEBUG(SSSDBG_CRIT_FAILURE, "Missing PIN.\n");
            return EINVAL;
        }

        buf = talloc_size(mem_ctx, len);
        if (buf == NULL) {
            DEBUG(SSSDBG_OP_FAILURE, "talloc_size failed.\n");
            return ENOMEM;
        }

        safealign_memcpy(buf, pin, len, NULL);

        break;
    default:
        DEBUG(SSSDBG_CRIT_FAILURE, "Unsupported authtok type [%d].\n",
                                   sss_authtok_get_type(pd->authtok));
        return EINVAL;
    }

    *_len = len;
    *_buf = buf;

    return EOK;
}

static void passkey_child_write_done(struct tevent_req *subreq)
{
    struct tevent_req *req = tevent_req_callback_data(subreq,
                                                      struct tevent_req);
    struct pam_passkey_auth_send_state *state = tevent_req_data(req, struct pam_passkey_auth_send_state);

    int ret;

    DEBUG(SSSDBG_TRACE_LIBS, "Sending passkey data complete\n");

    ret = write_pipe_recv(subreq);
    talloc_zfree(subreq);
    if (ret != EOK) {
        tevent_req_error(req, ret);
        return;
    }

    PIPE_FD_CLOSE(state->io->write_to_child_fd);
}

struct tevent_req *
pam_passkey_auth_send(TALLOC_CTX *mem_ctx,
                    struct tevent_context *ev,
                    int timeout,
                    bool debug_libfido2,
                    const char *verify_opts,
                    struct pam_data *pd)
{
    struct tevent_req *req;
    struct pam_passkey_auth_send_state *state;
    size_t arg_c = 0;
    int num_args;
    int ret;
    enum user_verification verify_setting = UNSET;

    req = tevent_req_create(mem_ctx, &state, struct pam_passkey_auth_send_state);
    if (req == NULL) {
        return NULL;
    }

    state->pd = pd;
    state->ev = ev;
    state->timeout = timeout;
    state->logfile = PASSKEY_CHILD_LOG_FILE;
    state->io = talloc(state, struct child_io_fds);
    if (state->io == NULL) {
        DEBUG(SSSDBG_OP_FAILURE, "talloc child fds failed.\n");
        ret = ENOMEM;
        goto done;
    }
    state->timeout = 60000;
    state->io->write_to_child_fd = -1;
    state->io->read_from_child_fd = -1;
    talloc_set_destructor((void *) state->io, child_io_destructor);

    num_args = 16;
    state->extra_args = talloc_zero_array(state, const char *, num_args + 1);
    if (state->extra_args == NULL) {
        DEBUG(SSSDBG_OP_FAILURE, "talloc_zero_array failed.\n");
        ret = ENOMEM;
        goto done;
    }

    /* Options retrieved from LDAP, combined with sssd.conf value (most restrictive) */
    ret = parse_passkey_verify_opts(state, verify_opts, &verify_setting);
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE, "Unable to parse passkey verificaton options.\n");
        goto done;
    }

    if (debug_libfido2) {
        state->extra_args[arg_c++] = "--debug-libfido2";
    }

    switch (verify_setting) {
        case ON:
            state->extra_args[arg_c++] = "--user-verification=true";
            break;
        case OFF:
            state->extra_args[arg_c++] = "--user-verification=false";
            break;
        /* passkey helper will assume "default" */
        case UNSET:
        default:
    }

    /* Options retrieved from LDAP */
    state->extra_args[arg_c++] = "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAENNqrxcBrbgvlAQYHi5mHCHSBaO8wBcwBDmufTf5Bnw2C8VSDHnYgt4WxDQOmigdlWPVTqLSjhLprETOUOQQwvQ==";
    state->extra_args[arg_c++] = "--public-key";
    state->extra_args[arg_c++] = "Y4dDZcwFGoN6/cJA386eoRFTWQwefF+2TyGCRTkzyjmRLZaODLEfpJPYnKGPW+SGudvTpbbYYeDbrBko/3g9+Q==";
    state->extra_args[arg_c++] = "--key-handle";
    state->extra_args[arg_c++] = "test.com";
    state->extra_args[arg_c++] = "--domain";
    state->extra_args[arg_c++] = "justin";
    state->extra_args[arg_c++] = "--username";
    state->extra_args[arg_c++] = "--authenticate";

    ret = passkey_child_exec(req);

done:
    if (ret == EOK) {
        tevent_req_done(req);
        tevent_req_post(req, ev);
    } else if (ret != EAGAIN) {
        tevent_req_error(req, ret);
        tevent_req_post(req, ev);
    }

    return req;
}

static errno_t passkey_child_exec(struct tevent_req *req)
{
    struct pam_passkey_auth_send_state *state;
    struct tevent_req *subreq;
    int pipefd_from_child[2] = PIPE_INIT;
    int pipefd_to_child[2] = PIPE_INIT;
    pid_t child_pid;
    uint8_t *write_buf;
    size_t write_buf_len = 0;
    struct timeval tv;
    bool endtime;
    int ret;

    state = tevent_req_data(req, struct pam_passkey_auth_send_state);

    ret = pipe(pipefd_from_child);
    if (ret == -1) {
        ret = errno;
        DEBUG(SSSDBG_CRIT_FAILURE,
              "pipe failed [%d][%s].\n", ret, strerror(ret));
        goto done;
    }
    ret = pipe(pipefd_to_child);
    if (ret == -1) {
        ret = errno;
        DEBUG(SSSDBG_CRIT_FAILURE,
              "pipe failed [%d][%s].\n", ret, strerror(ret));
        goto done;
    }

    child_pid = fork();
    if (child_pid == 0) { /* child */
        exec_child_ex(state, pipefd_to_child, pipefd_from_child,
                      PASSKEY_CHILD_PATH, state->logfile, state->extra_args,
                      false, STDIN_FILENO, STDOUT_FILENO);
        /* We should never get here */
        ret = errno;
        DEBUG(SSSDBG_CRIT_FAILURE, "BUG: Could not exec passkey child\n");
        return ret;
    } else if (child_pid > 0) { /* parent */
        state->io->read_from_child_fd = pipefd_from_child[0];
        PIPE_FD_CLOSE(pipefd_from_child[1]);
        sss_fd_nonblocking(state->io->read_from_child_fd);

        state->io->write_to_child_fd = pipefd_to_child[1];
        PIPE_FD_CLOSE(pipefd_to_child[0]);
        sss_fd_nonblocking(state->io->write_to_child_fd);

        /* Set up SIGCHLD handler */
        ret = child_handler_setup(state->ev, child_pid,
                                  pam_passkey_auth_done, req,
                                  &state->child_ctx);
        if (ret != EOK) {
            DEBUG(SSSDBG_OP_FAILURE, "Could not set up child handlers [%d]: %s\n",
                  ret, sss_strerror(ret));
            ret = ERR_PASSKEY_CHILD;
            goto done;
        }

        /* Set up timeout handler */
        tv = tevent_timeval_current_ofs(state->timeout, 0);
        endtime = tevent_req_set_endtime(req, state->ev, tv);
        if (endtime == false) {
            ret = ERR_PASSKEY_CHILD;
            goto done;
        }

	ret = get_passkey_child_write_buffer(state, state->pd, &write_buf,
				             &write_buf_len);
	if (ret != EOK) {
	    DEBUG(SSSDBG_OP_FAILURE,
	          "get_passkey_child_write_buffer failed.\n");
	    goto done;
	}

        if (write_buf_len != 0) {
            subreq = write_pipe_send(state, state->ev, write_buf, write_buf_len,
                                     state->io->write_to_child_fd);
            if (subreq == NULL) {
                DEBUG(SSSDBG_OP_FAILURE, "write_pipe_send failed.\n");
                ret = ERR_P11_CHILD;
                goto done;
            }
            tevent_req_set_callback(subreq, passkey_child_write_done, req);
        } else {
	    DEBUG(SSSDBG_OP_FAILURE,
	          "PIN required to perform passkey child auth.\n");
            ret = ERR_PASSKEY_CHILD;
	    goto done;
        }
        /* Now either wait for the timeout to fire or the child to finish */
    } else { /* error */
        ret = errno;
        DEBUG(SSSDBG_CRIT_FAILURE, "fork failed [%d][%s].\n",
              ret, sss_strerror(ret));
        goto done;
    }

    return EAGAIN;

done:
    if (ret != EOK) {
        PIPE_CLOSE(pipefd_from_child);
        PIPE_CLOSE(pipefd_to_child);
    }

    return ret;
}

errno_t pam_passkey_auth_recv(struct tevent_req *req, TALLOC_CTX *mem_ctx,
                            struct passkey_auth_data *passkey_data)
{
    struct pam_passkey_auth_send_state *state =
                              tevent_req_data(req, struct pam_passkey_auth_send_state);

    TEVENT_REQ_RETURN_ON_ERROR(req);

    passkey_data = state->passkey_data;

    return EOK;
}

static void
pam_passkey_auth_done(int child_status,
                    struct tevent_signal *sige,
                    void *pvt)
{
    struct tevent_req *req = talloc_get_type(pvt, struct tevent_req);

    if (WIFEXITED(child_status)) {
            if (WEXITSTATUS(child_status) != 0) {
            DEBUG(SSSDBG_OP_FAILURE,
                  PASSKEY_CHILD_PATH " failed with status [%d]. Check passkey_child"
                  " logs for more information.\n",
                  WEXITSTATUS(child_status));
            tevent_req_error(req, ERR_INVALID_CERT);
            return;
        }
    } else if (WIFSIGNALED(child_status)) {
        DEBUG(SSSDBG_OP_FAILURE,
              PASSKEY_CHILD_PATH " was terminated by signal [%d]. Check passkey_child"
              " logs for more information.\n",
              WTERMSIG(child_status));
        tevent_req_error(req, ECHILD);
        return;
    }

    DEBUG(SSSDBG_TRACE_LIBS, "passkey key is valid. Mark done\n");

    tevent_req_done(req);
    return;
}

bool may_do_passkey_auth(struct pam_ctx *pctx)
{
    if (!pctx->passkey_auth) {
        return false;
    }

    return true;
}

errno_t parse_passkey_verify_opts(TALLOC_CTX *mem_ctx,
                                const char *verify_opts,
                                enum user_verification *_user_verification)
{
    int ret;
    TALLOC_CTX *tmp_ctx;
    char **opts;
    size_t c;

    tmp_ctx = talloc_new(NULL);
    if (tmp_ctx == NULL) {
        DEBUG(SSSDBG_OP_FAILURE, "talloc_new failed.\n");
        return ENOMEM;
    }

    if (verify_opts == NULL) {
        ret = EOK;
        goto done;
    }

    ret = split_on_separator(tmp_ctx, verify_opts, ',', true, true, &opts,
                             NULL);
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE, "split_on_separator failed.\n");
        goto done;
    }

    for (c = 0; opts[c] != NULL; c++) {
        if (strcasecmp(opts[c], "user_verification") == 0) {
        } else if (strncasecmp(opts[c], USER_VERIFICATION, USER_VERIFICATION_LEN) == 0) {
            if (strcasecmp("true", &opts[c][USER_VERIFICATION_LEN]) == 0) {
                *_user_verification = ON;
                DEBUG(SSSDBG_TRACE_ALL, "user_verification set to true.\n");
            } else if (strcasecmp("false", &opts[c][USER_VERIFICATION_LEN]) == 0) {
                *_user_verification = OFF;
                DEBUG(SSSDBG_TRACE_ALL, "user_verification set to false.\n");
            }
        } else {
            DEBUG(SSSDBG_CRIT_FAILURE,
                  "Unsupported passkey verification option [%s], " \
                  "skipping.\n", opts[c]);
        }
    }

    ret = EOK;

done:
    talloc_free(tmp_ctx);

    return ret;
}
