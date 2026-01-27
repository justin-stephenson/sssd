/*
    SSSD

    Minimal Provider Kerberos Backend, private header file

    Authors:
        Justin Stephenson <jstephen@redhat.com>

    Copyright (C) 2026 Red Hat


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

#ifndef __MINIMAL_KRB5_AUTH_H__
#define __MINIMAL_KRB5_AUTH_H__


#include "util/sss_regexp.h"
#include "util/sss_krb5.h"
#include "providers/backend.h"
#include "providers/krb5/krb5_common.h"
#include "providers/krb5/krb5_ccache.h"

struct tevent_req *
minimal_krb5_pam_handler_send(TALLOC_CTX *mem_ctx,
                              struct krb5_ctx *krb5_ctx,
                              struct pam_data *pd,
                              struct dp_req_params *params);

errno_t
minimal_krb5_pam_handler_recv(TALLOC_CTX *mem_ctx,
                              struct tevent_req *req,
                              struct pam_data **_data);

#endif /* __MINIMAL_KRB5_AUTH_H__ */
