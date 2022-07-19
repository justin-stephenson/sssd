/*
    SSSD

    Helper child to commmunicate with FIDO2 devices

    Authors:
        Iker Pedrosa <ipedrosa@redhat.com>

    Copyright (C) 2022 Red Hat

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

#include <popt.h>
#include <sys/prctl.h>
#include <fido/param.h>

#include "util/debug.h"
#include "util/util.h"

#include "fido2_child.h"

static
int cose_type(const char *str, int *type) {
    if (strcasecmp(str, "es256") == 0) {
        *type = COSE_ES256;
    } else if (strcasecmp(str, "rs256") == 0) {
        *type = COSE_RS256;
    } else if (strcasecmp(str, "eddsa") == 0) {
        *type = COSE_EDDSA;
    } else {
        *type = 0;
        return 0;
    }

    printf("str %s, type %d\n", str, (*type));

    return 1;
}

int
fido2_parse_args(int argc, const char *argv[], struct options *options)
{
    int opt;
    int ret;
    int dumpable = 1;
    int debug_fd = -1;
    const char *opt_logger = NULL;
    const char *type = NULL;
    poptContext pc;

    // Set defaults
    options->action = ACTION_NONE;
    options->shortname = NULL;
    options->domain = NULL;
    options->public_key = NULL;
    options->key_handle = NULL;
    options->type = COSE_ES256;
    options->user_verification = false;
    options->user_presence = false;
    options->interactive = false;
    options->inter_prompt = NULL;
    options->touch = false;
    options->touch_prompt = NULL;
    options->debug_libfido2 = false;

    struct poptOption long_options[] = {
        POPT_AUTOHELP
        SSSD_DEBUG_OPTS
        {"register", 0, POPT_ARG_NONE, NULL, 'r',
         _("Register a FIDO2 key for a user"), NULL },
         {"authenticate", 0, POPT_ARG_NONE, NULL, 'a',
         _("Authenticate a user with a FIDO2 key"), NULL },
        {"username", 0, POPT_ARG_STRING, &options->shortname, 0,
         _("Shortname"), NULL },
        {"domain", 0, POPT_ARG_STRING, &options->domain, 0,
         _("Domain"), NULL},
        {"public-key", 0, POPT_ARG_STRING, &options->public_key, 0,
         _("Shortname"), NULL },
        {"key-handle", 0, POPT_ARG_STRING, &options->key_handle, 0,
         _("Domain"), NULL},
        {"type", 0, POPT_ARG_STRING, &type, 0,
         _("COSE type to use"), NULL},
        {"user-verification", 0, POPT_ARG_NONE, NULL, 'v',
         _("Require user verification during authentication"), NULL},
        {"user-presence", 0, POPT_ARG_NONE, NULL, 'p',
         _("Require user presence during authentication"), NULL},
        {"interactive", 0, POPT_ARG_NONE, NULL, 'i',
         _("Prompt a message and wait before testing the presence of a FIDO2 device"),
         NULL},
        {"interactive-prompt", 0, POPT_ARG_STRING, &options->inter_prompt, 0,
         _("Set individual prompt message for interactive mode."), NULL},
        {"touch", 0, POPT_ARG_NONE, NULL, 'c',
         _("Prompt a message to remind the user to touch the device"),
         NULL},
        {"touch-prompt", 0, POPT_ARG_STRING, &options->touch_prompt, 0,
         _("Set individual prompt message for the touch option"), NULL},
        {"debug-libfido2", 0, POPT_ARG_NONE, NULL, 'd',
         _("Enable debug in libfido2 library"), NULL},
        SSSD_LOGGER_OPTS
        POPT_TABLEEND
    };

    /* Set debug level to invalid value so we can decide if -d 0 was used. */
    debug_level = SSSDBG_INVALID;

    pc = poptGetContext(argv[0], argc, argv, long_options, 0);

    while((opt = poptGetNextOpt(pc)) != -1) {
        switch(opt) {
        case 'r':
            if (options->action != ACTION_NONE) {
                fprintf(stderr, "\n--register and --authenticate are mutually exclusive " \
                                "and should be used only once.\n\n");
                poptPrintUsage(pc, stderr, 0);
                _exit(-1);
            }
            options->action = ACTION_REGISTER;
            break;
        case 'a':
            if (options->action != ACTION_NONE) {
                fprintf(stderr, "\n--register and --authenticate are mutually exclusive " \
                                "and should be used only once.\n\n");
                poptPrintUsage(pc, stderr, 0);
                _exit(-1);
            }
            options->action = ACTION_AUTHENTICATE;
            break;
        case 'v':
            options->user_verification = true;
            break;
        case 'p':
            options->user_presence = true;
            break;
        case 'i':
            options->interactive = true;
            break;
        case 'c':
            options->touch = true;
            break;
        case 'd':
            options->debug_libfido2 = true;
            break;
        default:
            fprintf(stderr, "\nInvalid option %s: %s\n\n",
                  poptBadOption(pc, 0), poptStrerror(opt));
            poptPrintUsage(pc, stderr, 0);
            _exit(-1);
        }
    }

    poptFreeContext(pc);

    prctl(PR_SET_DUMPABLE, (dumpable == 0) ? 0 : 1);

    if (type != NULL) {
        cose_type(type, &options->type);
    }

    debug_prg_name = talloc_asprintf(NULL, "fido2_child[%d]", getpid());
    if (debug_prg_name == NULL) {
        ERROR("talloc_asprintf failed.\n");
        ret = ENOMEM;
        goto done;
    }

    if (debug_fd != -1) {
        opt_logger = sss_logger_str[FILES_LOGGER];
        ret = set_debug_file_from_fd(debug_fd);
        if (ret != EOK) {
            opt_logger = sss_logger_str[STDERR_LOGGER];
            ERROR("set_debug_file_from_fd failed.\n");
        }
    }

    DEBUG_INIT(debug_level, opt_logger);

    ret = EOK;

done:
    return ret;
}