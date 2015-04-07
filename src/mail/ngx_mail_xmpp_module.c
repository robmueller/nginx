
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Nginx, Inc.
 */


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_event.h>
#include <ngx_mail.h>
#include <ngx_mail_xmpp_module.h>


static void *ngx_mail_xmpp_create_srv_conf(ngx_conf_t *cf);
static char *ngx_mail_xmpp_merge_srv_conf(ngx_conf_t *cf, void *parent,
    void *child);


static ngx_conf_bitmask_t  ngx_mail_xmpp_auth_methods[] = {
    { ngx_string("plain"), NGX_MAIL_AUTH_PLAIN_ENABLED },
    { ngx_string("login"), NGX_MAIL_AUTH_LOGIN_ENABLED },
    { ngx_string("cram-md5"), NGX_MAIL_AUTH_CRAM_MD5_ENABLED },
    { ngx_null_string, 0 }
};


static ngx_str_t  ngx_mail_xmpp_auth_methods_names[] = {
    ngx_string("PLAIN"),
    ngx_string("LOGIN"),
    ngx_null_string,  /* APOP */
    ngx_string("CRAM-MD5"),
    ngx_null_string   /* NONE */
};

static u_char xmpp_mechanism_start[] =
    "<mechanism>";
static u_char xmpp_mechanism_end[] =
    "</mechanism>";


static ngx_mail_protocol_t  ngx_mail_xmpp_protocol = {
    ngx_string("xmpp"),
    { 5222, 5223 ,0, 0 },
    NGX_MAIL_XMPP_PROTOCOL,

    ngx_mail_xmpp_init_session,
    ngx_mail_xmpp_init_protocol,
    ngx_mail_xmpp_parse_command,
    ngx_mail_xmpp_auth_state,

    ngx_string(
        "<stream:error>"
        "<internal-server-error xmlns=\"urn:ietf:params:xml:ns:xmpp-streams\"/>"
        "</stream:error>"
        "</stream:stream>"
    ),
    ngx_string(
        "<stream:error>"
        "<policy-violation xmlns=\"urn:ietf:params:xml:ns:xmpp-streams\"/>"
        "<text xmlns=\"urn:ietf:params:xml:ns:xmpp-streams\" xml:lang=\"en\">SSL certificate error</text>"
        "</stream:error>"
        "</stream:stream>"
    ),
    ngx_string(
        "<stream:error>"
        "<policy-violation xmlns=\"urn:ietf:params:xml:ns:xmpp-streams\"/>"
        "<text xmlns=\"urn:ietf:params:xml:ns:xmpp-streams\" xml:lang=\"en\">No required SSL certificate</text>"
        "</stream:error>"
        "</stream:stream>"
    )
};


static ngx_command_t  ngx_mail_xmpp_commands[] = {

    { ngx_string("xmpp_client_buffer"),
      NGX_MAIL_MAIN_CONF|NGX_MAIL_SRV_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_size_slot,
      NGX_MAIL_SRV_CONF_OFFSET,
      offsetof(ngx_mail_xmpp_srv_conf_t, client_buffer_size),
      NULL },

    { ngx_string("xmpp_auth"),
      NGX_MAIL_MAIN_CONF|NGX_MAIL_SRV_CONF|NGX_CONF_1MORE,
      ngx_conf_set_bitmask_slot,
      NGX_MAIL_SRV_CONF_OFFSET,
      offsetof(ngx_mail_xmpp_srv_conf_t, auth_methods),
      &ngx_mail_xmpp_auth_methods },

      ngx_null_command
};


static ngx_mail_module_t  ngx_mail_xmpp_module_ctx = {
    &ngx_mail_xmpp_protocol,               /* protocol */

    NULL,                                  /* create main configuration */
    NULL,                                  /* init main configuration */

    ngx_mail_xmpp_create_srv_conf,         /* create server configuration */
    ngx_mail_xmpp_merge_srv_conf           /* merge server configuration */
};


ngx_module_t  ngx_mail_xmpp_module = {
    NGX_MODULE_V1,
    &ngx_mail_xmpp_module_ctx,             /* module context */
    ngx_mail_xmpp_commands,                /* module directives */
    NGX_MAIL_MODULE,                       /* module type */
    NULL,                                  /* init master */
    NULL,                                  /* init module */
    NULL,                                  /* init process */
    NULL,                                  /* init thread */
    NULL,                                  /* exit thread */
    NULL,                                  /* exit process */
    NULL,                                  /* exit master */
    NGX_MODULE_V1_PADDING
};


static void *
ngx_mail_xmpp_create_srv_conf(ngx_conf_t *cf)
{
    ngx_mail_xmpp_srv_conf_t  *xscf;

    xscf = ngx_pcalloc(cf->pool, sizeof(ngx_mail_xmpp_srv_conf_t));
    if (xscf == NULL) {
        return NULL;
    }

    xscf->client_buffer_size = NGX_CONF_UNSET_SIZE;

    return xscf;
}


static char *
ngx_mail_xmpp_merge_srv_conf(ngx_conf_t *cf, void *parent, void *child)
{
    ngx_mail_xmpp_srv_conf_t *prev = parent;
    ngx_mail_xmpp_srv_conf_t *conf = child;

    u_char      *p;
    size_t       size;
    ngx_uint_t   i, m;

    ngx_conf_merge_size_value(conf->client_buffer_size,
                              prev->client_buffer_size,
                              (size_t) ngx_pagesize);

    ngx_conf_merge_bitmask_value(conf->auth_methods,
                              prev->auth_methods,
                              (NGX_CONF_BITMASK_SET
                               |NGX_MAIL_AUTH_PLAIN_ENABLED
                               |NGX_MAIL_AUTH_LOGIN_ENABLED));


    size = 0;

    for (m = NGX_MAIL_AUTH_PLAIN_ENABLED, i = 0;
         m <= NGX_MAIL_AUTH_CRAM_MD5_ENABLED;
         m <<= 1, i++)
    {
        if (m & conf->auth_methods) {
            size += sizeof(xmpp_mechanism_start) - 1
                  + ngx_mail_xmpp_auth_methods_names[i].len
                  + sizeof(xmpp_mechanism_end) - 1;
        }
    }

    p = ngx_pnalloc(cf->pool, size);
    if (p == NULL) {
        return NGX_CONF_ERROR;
    }

    conf->auth_mechanisms.len = size;
    conf->auth_mechanisms.data = p;

    for (m = NGX_MAIL_AUTH_PLAIN_ENABLED, i = 0;
         m <= NGX_MAIL_AUTH_CRAM_MD5_ENABLED;
         m <<= 1, i++)
    {
        if (m & conf->auth_methods) {
            p = ngx_cpymem(p, xmpp_mechanism_start, sizeof(xmpp_mechanism_start) - 1);
            p = ngx_cpymem(p, ngx_mail_xmpp_auth_methods_names[i].data, ngx_mail_xmpp_auth_methods_names[i].len);
            p = ngx_cpymem(p, xmpp_mechanism_end, sizeof(xmpp_mechanism_end) - 1);
        }
    }

    return NGX_CONF_OK;
}
