/*
    SSSD

    minimal Provider Initialization functions

    Authors:
        Justin Stephenson <jstephen@redhat.com>

    Copyright (C) 2025 Red Hat

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

#include "src/providers/data_provider.h"
#include "providers/ldap/ldap_common.h"
#include "providers/ldap/ldap_opts.h"
#include "providers/ldap/sdap_async_private.h"
#include "providers/ldap/sdap_access.h"
#include "providers/ldap/ldap_resolver_enum.h"
#include "providers/fail_over_srv.h"
#include "providers/be_refresh.h"

#include "src/providers/minimal/minimal.h"
#include "src/providers/minimal/minimal_id.h"

/* Copied from krb5_init.c */
#include <sys/types.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>
#include "providers/krb5/krb5_auth.h"
#include "providers/krb5/krb5_common.h"
#include "providers/krb5/krb5_init_shared.h"
#include "providers/data_provider.h"

/* Copied from ldap_init.c with no changes */
static errno_t get_sdap_service(TALLOC_CTX *mem_ctx,
                                struct be_ctx *be_ctx,
                                struct sdap_options *opts,
                                struct sdap_service **_sdap_service)
{
    errno_t ret;
    const char *urls;
    const char *backup_urls;
    const char *dns_service_name;
    struct sdap_service *sdap_service;

    urls = dp_opt_get_string(opts->basic, SDAP_URI);
    backup_urls = dp_opt_get_string(opts->basic, SDAP_BACKUP_URI);
    dns_service_name = dp_opt_get_string(opts->basic, SDAP_DNS_SERVICE_NAME);
    if (dns_service_name != NULL) {
        DEBUG(SSSDBG_CONF_SETTINGS,
              "Service name for discovery set to %s\n", dns_service_name);
    }

    ret = sdap_service_init(mem_ctx, be_ctx, "LDAP",
                            dns_service_name,
                            urls,
                            backup_urls,
                            &sdap_service);
    if (ret != EOK) {
        return ret;
    }

    *_sdap_service = sdap_service;
    return EOK;
}

/* Copied from ldap_init.c with some changes
 * removing calls to
 * - sdap_gssapi_init()
 * - sdap_idmap_init()
 * - confdb_certmap_to_sysdb()
 * - sdap_init_certmap() */
static errno_t ldap_init_misc(struct be_ctx *be_ctx,
                              struct sdap_options *options,
                              struct sdap_id_ctx *id_ctx)
{
    errno_t ret;

    setup_ldap_debug(options->basic);

    ret = setup_tls_config(options->basic);
    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Unable to get TLS options [%d]: %s\n",
              ret, sss_strerror(ret));
        return ret;
    }

    ret = ldap_id_setup_tasks(id_ctx);
    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Unable to setup background tasks "
              "[%d]: %s\n", ret, sss_strerror(ret));
        return ret;
    }

    /* Setup SRV lookup plugin */
    ret = be_fo_set_dns_srv_lookup_plugin(be_ctx, NULL);
    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Unable to set SRV lookup plugin "
              "[%d]: %s\n", ret, sss_strerror(ret));
        return ret;
    }

    /* Setup periodical refresh of expired records */
    ret = sdap_refresh_init(be_ctx, id_ctx);
    if (ret != EOK && ret != EEXIST) {
        DEBUG(SSSDBG_MINOR_FAILURE, "Periodical refresh will not work "
              "[%d]: %s\n", ret, sss_strerror(ret));
    }

    return EOK;
}

/* Copied from krb5_init.c */
static errno_t krb5_init_kpasswd(struct krb5_ctx *ctx,
                                 struct be_ctx *be_ctx)
{
    const char *realm;
    const char *primary_servers;
    const char *backup_servers;
    const char *kdc_servers;
    bool use_kdcinfo;
    size_t n_lookahead_primary;
    size_t n_lookahead_backup;
    errno_t ret;

    realm = dp_opt_get_string(ctx->opts, KRB5_REALM);
    if (realm == NULL) {
        DEBUG(SSSDBG_FATAL_FAILURE, "Missing krb5_realm option!\n");
        return EINVAL;
    }

    kdc_servers = dp_opt_get_string(ctx->opts, KRB5_KDC);
    primary_servers = dp_opt_get_string(ctx->opts, KRB5_KPASSWD);
    backup_servers = dp_opt_get_string(ctx->opts, KRB5_BACKUP_KPASSWD);
    use_kdcinfo = dp_opt_get_bool(ctx->opts, KRB5_USE_KDCINFO);
    sss_krb5_parse_lookahead(dp_opt_get_string(ctx->opts, KRB5_KDCINFO_LOOKAHEAD),
                             &n_lookahead_primary, &n_lookahead_backup);


    if (primary_servers == NULL && backup_servers != NULL) {
        DEBUG(SSSDBG_CONF_SETTINGS, "kpasswd server wasn't specified but "
              "backup_servers kpasswd given. Using it as primary_servers\n");
        primary_servers = backup_servers;
        backup_servers = NULL;
    }

    if (primary_servers == NULL && kdc_servers != NULL) {
        DEBUG(SSSDBG_FATAL_FAILURE, "Missing krb5_kpasswd option and KDC set "
              "explicitly, will use KDC for password change operations!\n");
        ctx->kpasswd_service = NULL;
    } else {
        ret = krb5_service_init(ctx, be_ctx, SSS_KRB5KPASSWD_FO_SRV,
                                primary_servers, backup_servers, realm,
                                use_kdcinfo,
                                n_lookahead_primary,
                                n_lookahead_backup,
                                &ctx->kpasswd_service);
        if (ret != EOK) {
            DEBUG(SSSDBG_FATAL_FAILURE,
                  "Failed to init KRB5KPASSWD failover service!\n");
            return ret;
        }
    }

    return EOK;
}


/* Copied from krb5_init.c */
static errno_t krb5_init_kdc(struct krb5_ctx *ctx, struct be_ctx *be_ctx)
{
    const char *primary_servers;
    const char *backup_servers;
    const char *realm;
    bool use_kdcinfo;
    size_t n_lookahead_primary;
    size_t n_lookahead_backup;
    errno_t ret;

    realm = dp_opt_get_string(ctx->opts, KRB5_REALM);
    if (realm == NULL) {
        DEBUG(SSSDBG_FATAL_FAILURE, "Missing krb5_realm option!\n");
        return EINVAL;
    }

    primary_servers = dp_opt_get_string(ctx->opts, KRB5_KDC);
    backup_servers = dp_opt_get_string(ctx->opts, KRB5_BACKUP_KDC);

    use_kdcinfo = dp_opt_get_bool(ctx->opts, KRB5_USE_KDCINFO);
    sss_krb5_parse_lookahead(dp_opt_get_string(ctx->opts, KRB5_KDCINFO_LOOKAHEAD),
                             &n_lookahead_primary, &n_lookahead_backup);

    ret = krb5_service_init(ctx, be_ctx, SSS_KRB5KDC_FO_SRV,
                            primary_servers, backup_servers, realm,
                            use_kdcinfo,
                            n_lookahead_primary,
                            n_lookahead_backup,
                            &ctx->service);
    if (ret != EOK) {
        DEBUG(SSSDBG_FATAL_FAILURE, "Failed to init KRB5 failover service!\n");
        return ret;
    }

    return EOK;
}

/* sssm_krb5_init() copied just renamed from krb5_init.c */
errno_t minimal_init_auth_ctx(TALLOC_CTX *mem_ctx,
                              struct be_ctx *be_ctx,
                              struct data_provider *provider,
                              const char *module_name,
                              struct krb5_ctx **_module_data)
{
    struct krb5_ctx *ctx;
    errno_t ret;

    ctx = talloc_zero(mem_ctx, struct krb5_ctx);
    if (ctx == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "talloc_zero() failed\n");
        return ENOMEM;
    }

    ret = sss_krb5_get_options(ctx, be_ctx->cdb, be_ctx->conf_path, &ctx->opts);
    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Unable to get krb5 options [%d]: %s\n",
              ret, sss_strerror(ret));
        goto done;
    }

    ctx->action = INIT_PW;
    ctx->config_type = K5C_GENERIC;

    ret = krb5_init_kdc(ctx, be_ctx);
    if (ret != EOK) {
        goto done;
    }

    ret = krb5_init_kpasswd(ctx, be_ctx);
    if (ret != EOK) {
        goto done;
    }

    ret = krb5_child_init(ctx, be_ctx);
    if (ret != EOK) {
        DEBUG(SSSDBG_FATAL_FAILURE, "Could not initialize krb5_child settings "
              "[%d]: %s\n", ret, sss_strerror(ret));
        goto done;
    }

    ret = sss_regexp_new(ctx, ILLEGAL_PATH_PATTERN, 0, &(ctx->illegal_path_re));
    if (ret != EOK) {
        ret = EFAULT;
        goto done;
    }

    ret = be_fo_set_dns_srv_lookup_plugin(be_ctx, NULL);
    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Unable to set SRV lookup plugin "
              "[%d]: %s\n", ret, sss_strerror(ret));
        goto done;
    }

    *_module_data = ctx;

    ret = EOK;

done:
    if (ret != EOK) {
        talloc_free(ctx);
    }

    return ret;
}


errno_t sssm_minimal_init(TALLOC_CTX *mem_ctx,
                      struct be_ctx *be_ctx,
                      struct data_provider *provider,
                      const char *module_name,
                      void **_module_data)
{
    struct sdap_service *sdap_service;
    struct minimal_init_ctx *init_ctx;
    errno_t ret;

    init_ctx = talloc_zero(mem_ctx, struct minimal_init_ctx);
    if (init_ctx == NULL) {
        return ENOMEM;
    }

    /* Always initialize options since it is needed everywhere. */
    ret = ldap_get_options(init_ctx, be_ctx->domain, be_ctx->cdb,
                           be_ctx->conf_path, be_ctx->provider,
                           &init_ctx->options);
    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Unable to initialize LDAP options "
              "[%d]: %s\n", ret, sss_strerror(ret));
        goto done;
    }

    /* Always initialize id_ctx since it is needed everywhere. */
    ret = get_sdap_service(init_ctx, be_ctx, init_ctx->options, &sdap_service);
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE, "Failed to initialize failover service "
              "[%d]: %s\n", ret, sss_strerror(ret));
        goto done;
    }

    init_ctx->id_ctx = sdap_id_ctx_new(init_ctx, be_ctx, sdap_service);
    if (init_ctx->id_ctx == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Unable to initialize LDAP ID context\n");
        ret = ENOMEM;
        goto done;
    }

    init_ctx->id_ctx->opts = init_ctx->options;

    /* Setup miscellaneous things. */
    ret = ldap_init_misc(be_ctx, init_ctx->options, init_ctx->id_ctx);
    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Unable to init LDAP module "
              "[%d]: %s\n", ret, sss_strerror(ret));
        goto done;
    }

    /* Initialize krb5 auth_ctx only if DPT_AUTH target is enabled. */
    if (dp_target_enabled(provider, module_name, DPT_AUTH)) {
        ret = minimal_init_auth_ctx(init_ctx, be_ctx, provider,
                                    module_name, &init_ctx->auth_ctx);
        if (ret != EOK) {
            DEBUG(SSSDBG_CRIT_FAILURE, "Unable to create auth context "
                  "[%d]: %s\n", ret, sss_strerror(ret));
            return ret;
        }
    }

    *_module_data = init_ctx;

    ret = EOK;

done:
    if (ret != EOK) {
        talloc_free(init_ctx);
    }

    return ret;
}

errno_t sssm_minimal_id_init(TALLOC_CTX *mem_ctx,
                         struct be_ctx *be_ctx,
                         void *module_data,
                         struct dp_method *dp_methods)
{
    struct minimal_init_ctx *init_ctx;
    errno_t ret;

    init_ctx = talloc_get_type(module_data, struct minimal_init_ctx);

    dp_set_method(dp_methods, DPM_ACCOUNT_HANDLER,
                  minimal_account_info_handler_send, minimal_account_info_handler_recv, init_ctx,
                  struct minimal_init_ctx, struct dp_id_data, struct dp_reply_std);

    /* LDAP provider check online handler */
    dp_set_method(dp_methods, DPM_CHECK_ONLINE,
                  sdap_online_check_handler_send, sdap_online_check_handler_recv, init_ctx->id_ctx,
                  struct sdap_id_ctx, void, struct dp_reply_std);

    dp_set_method(dp_methods, DPM_ACCT_DOMAIN_HANDLER,
                  default_account_domain_send, default_account_domain_recv, NULL,
                  void, struct dp_get_acct_domain_data, struct dp_reply_std);

    ret = EOK;

    return ret;
}

errno_t sssm_minimal_auth_init(TALLOC_CTX *mem_ctx,
                               struct be_ctx *be_ctx,
                               void *module_data,
                               struct dp_method *dp_methods)
{
    struct minimal_init_ctx *init_ctx;

    init_ctx = talloc_get_type(module_data, struct minimal_init_ctx);

    dp_set_method(dp_methods, DPM_AUTH_HANDLER,
                  krb5_pam_handler_send, krb5_pam_handler_recv, init_ctx->auth_ctx,
                  struct krb5_ctx, struct pam_data, struct pam_data *);

    return EOK;
}
