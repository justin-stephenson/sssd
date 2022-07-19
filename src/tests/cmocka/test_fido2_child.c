/*
    SSSD

    Unit test helper child to commmunicate with FIDO2 devices

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
#include <popt.h>

#include "tests/cmocka/common_mock.h"

#include "fido2_child/fido2_child.h"


void test_parse_required_args(void **state)
{
    struct options options;
    int argc = 0;
    const char *argv[19] = { NULL };
    int ret;

    argv[argc++] = "fido2_child";
    argv[argc++] = "--register";
    argv[argc++] = "--username=user";
    argv[argc++] = "--domain=test.com";
    argv[argc++] = "--public-key=publicKey";
    argv[argc++] = "--key-handle=keyHandle";

    ret = fido2_parse_args(argc, argv, &options);

    assert_int_equal(ret, 0);
    assert_int_equal(options.action, ACTION_REGISTER);
    assert_string_equal(options.shortname, "user");
    assert_string_equal(options.domain, "test.com");
    assert_string_equal(options.public_key, "publicKey");
    assert_string_equal(options.key_handle, "keyHandle");
    assert_int_equal(options.type, COSE_ES256);
    assert_int_equal(options.user_verification, false);
    assert_int_equal(options.user_presence, false);
    assert_int_equal(options.interactive, false);
    assert_null(options.inter_prompt);
    assert_int_equal(options.touch, false);
    assert_null(options.touch_prompt);
    assert_int_equal(options.debug_libfido2, false);
}

void test_parse_all_args(void **state)
{
    struct options options;
    int argc = 0;
    const char *argv[19] = { NULL };
    int ret;

    argv[argc++] = "fido2_child";
    argv[argc++] = "--authenticate";
    argv[argc++] = "--username=user";
    argv[argc++] = "--domain=test.com";
    argv[argc++] = "--public-key=publicKey";
    argv[argc++] = "--key-handle=keyHandle";
    argv[argc++] = "--type=rs256";
    argv[argc++] = "--user-verification";
    argv[argc++] = "--user-presence";
    argv[argc++] = "--interactive";
    argv[argc++] = "--interactive-prompt=Prompt:";
    argv[argc++] = "--touch";
    argv[argc++] = "--touch-prompt=Another prompt:";
    argv[argc++] = "--debug-libfido2";

    ret = fido2_parse_args(argc, argv, &options);

    assert_int_equal(ret, 0);
    assert_int_equal(options.action, ACTION_AUTHENTICATE);
    assert_string_equal(options.shortname, "user");
    assert_string_equal(options.domain, "test.com");
    assert_string_equal(options.public_key, "publicKey");
    assert_string_equal(options.key_handle, "keyHandle");
    assert_int_equal(options.type, COSE_RS256);
    assert_int_equal(options.user_verification, true);
    assert_int_equal(options.user_presence, true);
    assert_int_equal(options.interactive, true);
    assert_string_equal(options.inter_prompt, "Prompt:");
    assert_int_equal(options.touch, true);
    assert_string_equal(options.touch_prompt, "Another prompt:");
    assert_int_equal(options.debug_libfido2, true);
}

int main(int argc, const char *argv[])
{
    poptContext pc;
    int opt;
    struct poptOption long_options[] = {
        POPT_AUTOHELP
        SSSD_DEBUG_OPTS
        POPT_TABLEEND
    };

    const struct CMUnitTest tests[] = {
        cmocka_unit_test(test_parse_required_args),
        cmocka_unit_test(test_parse_all_args),
    };

    /* Set debug level to invalid value so we can decide if -d 0 was used. */
    debug_level = SSSDBG_INVALID;

    pc = poptGetContext(argv[0], argc, argv, long_options, 0);
    while((opt = poptGetNextOpt(pc)) != -1) {
        switch(opt) {
        default:
            fprintf(stderr, "\nInvalid option %s: %s\n\n",
                    poptBadOption(pc, 0), poptStrerror(opt));
            poptPrintUsage(pc, stderr, 0);
            return 1;
        }
    }
    poptFreeContext(pc);

    DEBUG_CLI_INIT(debug_level);

    /* Even though normally the tests should clean up after themselves
     * they might not after a failed run. Remove the old DB to be sure */
    tests_set_cwd();

    return cmocka_run_group_tests(tests, NULL, NULL);
}
