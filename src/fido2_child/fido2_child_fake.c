/*
    SSSD

    Fake helper child to commmunicate with FIDO2 devices

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

#include <fido/param.h>

#include "util/debug.h"
#include "util/util.h"

#include "fido2_child.h"

int main(int argc, const char *argv[])
{
    struct options options;
    int ret;

    ret = fido2_parse_args(argc, argv, &options);
    if (ret != EOK) {
        return EXIT_FAILURE;
    }

    DEBUG(SSSDBG_TRACE_FUNC, "fido2_child started.\n");

    if (options.action == ACTION_NONE) {
        return EXIT_FAILURE;
    }

    if (options.action == ACTION_REGISTER && (options.shortname == NULL
       || options.domain == NULL)) {
        return EXIT_FAILURE;
    }

    if (options.action == ACTION_AUTHENTICATE && (options.shortname == NULL
       || options.domain == NULL || options.public_key == NULL
       || options.key_handle == NULL)) {
        return EXIT_FAILURE;
    }

    DEBUG(SSSDBG_TRACE_FUNC, "Argument values after parsing\n");
    DEBUG(SSSDBG_TRACE_FUNC, "action: %d\n", options.action);
    DEBUG(SSSDBG_TRACE_FUNC, "shortname: %s, domain: %s\n", options.shortname, options.domain);
    DEBUG(SSSDBG_TRACE_FUNC, "public_key: %s, key_handle: %s\n", options.public_key, options.key_handle);
    DEBUG(SSSDBG_TRACE_FUNC, "type: %d\n", options.type);
    DEBUG(SSSDBG_TRACE_FUNC, "user_verification: %d, user_presence: %d\n", options.user_verification, options.user_presence);
    DEBUG(SSSDBG_TRACE_FUNC, "interactive: %d, interactive_prompt %s\n", options.interactive, options.inter_prompt);
    DEBUG(SSSDBG_TRACE_FUNC, "touch: %d, touch_prompt %s\n", options.touch, options.touch_prompt);
    DEBUG(SSSDBG_TRACE_FUNC, "debug_libfido2: %d\n", options.debug_libfido2);

    return EXIT_SUCCESS;
}