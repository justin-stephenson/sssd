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

#define DEFAULT_PROMPT "Insert your FIDO2 device, then press ENTER."
#define DEFAULT_CUE "Please touch the device."

enum action_opt {
    ACTION_NONE,
    ACTION_REGISTER,
    ACTION_AUTHENTICATE
};

struct options {
    enum action_opt action;
    const char *shortname;
    const char *domain;
    char *public_key;
    char *key_handle;
    int type;
    bool user_verification;
    bool user_presence;
    bool interactive;
    const char *inter_prompt;
    bool touch;
    const char *touch_prompt;
    bool debug_libfido2;
};

int
fido2_parse_args(int argc, const char *argv[], struct options *options);