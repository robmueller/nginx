
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Nginx, Inc.
 */


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_event.h>
#include <ngx_mail.h>
#include <ngx_mail_xmpp_module.h>


static ngx_int_t ngx_mail_xmpp_stream(ngx_mail_session_t *s,
    ngx_connection_t *c);
static ngx_int_t ngx_mail_xmpp_starttls(ngx_mail_session_t *s,
    ngx_connection_t *c);
static ngx_int_t ngx_mail_xmpp_auth(ngx_mail_session_t *s,
    ngx_connection_t *c);
static void ngx_mail_xmpp_auth_fixup(ngx_mail_session_t *s,
    ngx_connection_t *c);


static u_char xmpp_stream_header_from[] =
    "<?xml version=\"1.0\" encoding=\"UTF-8\"?>"
    "<stream:stream version=\"1.0\" xmlns:stream=\"http://etherx.jabber.org/streams\" xmlns=\"jabber:client\" from=\"";
static u_char xmpp_stream_header_id[] =
    "\" id=\"";
static u_char xmpp_stream_header_features[] =
    "\"><stream:features>";
static u_char xmpp_stream_feature_starttls[] =
    "<starttls xmlns=\"urn:ietf:params:xml:ns:xmpp-tls\"/>";
static u_char xmpp_stream_feature_starttls_required[] =
    "<starttls xmlns=\"urn:ietf:params:xml:ns:xmpp-tls\"><required/></starttls>";
static u_char xmpp_stream_feature_sasl_start[] =
    "<mechanisms xmlns=\"urn:ietf:params:xml:ns:xmpp-sasl\">";
static u_char xmpp_stream_feature_sasl_end[] =
    "</mechanisms>";
static u_char xmpp_stream_header_end[] =
    "</stream:features>";

#if (NGX_MAIL_SSL)
static u_char xmpp_starttls_proceed[] =
    "<proceed xmlns=\"urn:ietf:params:xml:ns:xmpp-tls\"/>";
#endif

static u_char  xmpp_auth_login_username_challenge[] =
    "<challenge xmlns=\"urn:ietf:params:xml:ns:xmpp-sasl\">VXNlcm5hbWU6</challenge>";
static u_char  xmpp_auth_login_password_challenge[] =
    "<challenge xmlns=\"urn:ietf:params:xml:ns:xmpp-sasl\">UGFzc3dvcmQ6</challenge>";
static u_char  xmpp_auth_plain_challenge[] =
    "<challenge xmlns=\"urn:ietf:params:xml:ns:xmpp-sasl\"/>";

#define XMPP_STREAM_UNDEFINED_CONDITION \
    "<stream:error>" \
    "<undefined-condition xmlns=\"urn:ietf:params:xml:ns:xmpp-streams\"/>" \
    "</stream:error>"

#define XMPP_STREAM_CLOSE \
    "</stream:stream>"

static u_char  xmpp_stream_close[] =
    XMPP_STREAM_CLOSE;

static u_char  xmpp_error_undefined_condition[] =
    XMPP_STREAM_UNDEFINED_CONDITION
    XMPP_STREAM_CLOSE;

static u_char  xmpp_error_stream_undefined_condition[] =
    "<?xml version=\"1.0\" encoding=\"UTF-8\"?>"
    "<stream:stream version=\"1.0\" xmlns:stream=\"http://etherx.jabber.org/streams\">"
    XMPP_STREAM_UNDEFINED_CONDITION
    XMPP_STREAM_CLOSE;


void
ngx_mail_xmpp_init_session(ngx_mail_session_t *s, ngx_connection_t *c)
{
    ngx_mail_core_srv_conf_t  *cscf;

    cscf = ngx_mail_get_module_srv_conf(s, ngx_mail_core_module);

    c->read->handler = ngx_mail_xmpp_init_protocol;

    ngx_add_timer(c->read, cscf->timeout);

    if (ngx_handle_read_event(c->read, 0) != NGX_OK) {
        ngx_mail_close_connection(c);
    }

    ngx_mail_send(c->write);
}


void
ngx_mail_xmpp_init_protocol(ngx_event_t *rev)
{
    ngx_connection_t          *c;
    ngx_mail_session_t        *s;
    ngx_mail_xmpp_srv_conf_t  *iscf;

    c = rev->data;

    c->log->action = "in auth state";

    if (rev->timedout) {
        ngx_log_error(NGX_LOG_INFO, c->log, NGX_ETIMEDOUT, "client timed out");
        c->timedout = 1;
        ngx_mail_close_connection(c);
        return;
    }

    s = c->data;

    if (s->buffer == NULL) {
        if (ngx_array_init(&s->args, c->pool, 2, sizeof(ngx_str_t))
            == NGX_ERROR)
        {
            ngx_mail_session_internal_server_error(s);
            return;
        }

        iscf = ngx_mail_get_module_srv_conf(s, ngx_mail_xmpp_module);

        s->buffer = ngx_create_temp_buf(c->pool, iscf->client_buffer_size);
        if (s->buffer == NULL) {
            ngx_mail_session_internal_server_error(s);
            return;
        }
    }

    s->mail_state = ngx_xmpp_start;
    c->read->handler = ngx_mail_xmpp_auth_state;

    ngx_mail_xmpp_auth_state(rev);
}


void
ngx_mail_xmpp_auth_state(ngx_event_t *rev)
{
    ngx_int_t            rc, do_close;
    ngx_connection_t    *c;
    ngx_mail_session_t  *s;

    do_close = 0;

    c = rev->data;
    s = c->data;

    ngx_log_debug0(NGX_LOG_DEBUG_MAIL, c->log, 0, "xmpp auth state");

    if (rev->timedout) {
        ngx_log_error(NGX_LOG_INFO, c->log, NGX_ETIMEDOUT, "client timed out");
        c->timedout = 1;
        ngx_mail_close_connection(c);
        return;
    }

    if (s->out.len) {
        ngx_log_debug0(NGX_LOG_DEBUG_MAIL, c->log, 0, "xmpp send handler busy");
        s->blocked = 1;
        return;
    }

    s->blocked = 0;

    rc = ngx_mail_read_command(s, c);

    if (rc == NGX_AGAIN || rc == NGX_ERROR) {
        return;
    }

    s->text.len = 0;

    if (rc == NGX_OK) {
        ngx_log_debug1(NGX_LOG_DEBUG_MAIL, c->log, 0, "xmpp auth command: %i",
                       s->command);

        switch (s->mail_state) {

        case ngx_xmpp_start:

            switch (s->command) {

            case NGX_XMPP_STREAM:
                rc = ngx_mail_xmpp_stream(s, c);
                break;

            default:
                rc = NGX_MAIL_PARSE_INVALID_COMMAND;
                break;
            }

            break;

        case ngx_xmpp_stream:

            switch (s->command) {

            case NGX_XMPP_STARTTLS:
                rc = ngx_mail_xmpp_starttls(s, c);
                break;

            case NGX_XMPP_AUTH:
                rc = ngx_mail_xmpp_auth(s, c);
                break;

            case NGX_XMPP_STREAM:
                ngx_str_set(&s->out, xmpp_stream_close);
                do_close = 1;
                break;

            default:
                rc = NGX_MAIL_PARSE_INVALID_COMMAND;
                break;

            }

            break;

        case ngx_xmpp_auth_login_username:
            rc = ngx_mail_auth_login_username(s, c, 0);

            ngx_str_set(&s->out, xmpp_auth_login_password_challenge);
            s->mail_state = ngx_xmpp_auth_login_password;

            break;

        case ngx_xmpp_auth_login_password:
            rc = ngx_mail_auth_login_password(s, c);
            break;

        case ngx_xmpp_auth_plain:
            rc = ngx_mail_auth_plain(s, c, 0);
            break;

        }
    }

    switch (rc) {

    case NGX_DONE:
        s->buffer->pos = s->buffer->last;

        ngx_mail_xmpp_auth_fixup(s, c);
        return;

    case NGX_ERROR:
        ngx_mail_session_internal_server_error(s);
        return;

    case NGX_MAIL_PARSE_INVALID_COMMAND:
        s->state = 0;

        if (s->mail_state == ngx_xmpp_start) {
            ngx_str_set(&s->out, xmpp_error_stream_undefined_condition);
        }
        else {
            ngx_str_set(&s->out, xmpp_error_undefined_condition);
            s->mail_state = ngx_xmpp_start;
        }
        do_close = 1;
        break;
    }

    s->args.nelts = 0;

    if (s->buffer->pos == s->buffer->last) {
        s->buffer->pos = s->buffer->start;
        s->buffer->last = s->buffer->start;
    }

    ngx_mail_send(c->write);

    if (do_close) {
        ngx_mail_close_connection(c);
    }
}

static ngx_int_t
ngx_mail_xmpp_id(ngx_mail_session_t *s, ngx_connection_t *c)
{
    s->salt.data = ngx_pnalloc(c->pool,
                               sizeof("18446744073709551616.") - 1
                               + NGX_TIME_T_LEN);
    if (s->salt.data == NULL) {
        return NGX_ERROR;
    }

    s->salt.len = ngx_sprintf(s->salt.data, "%ul.%T",
                              ngx_random(), ngx_time())
                  - s->salt.data;

    return NGX_OK;
}

static ngx_int_t
ngx_mail_xmpp_stream(ngx_mail_session_t *s, ngx_connection_t *c)
{
    ngx_str_t *arg;
    ngx_uint_t len;
    u_char *p, *out;
    ngx_uint_t starttls_on, starttls_only;
    ngx_mail_xmpp_srv_conf_t *xscf;

    if (s->mail_state != ngx_xmpp_start) {
        return NGX_MAIL_PARSE_INVALID_COMMAND;
    }

    arg = s->args.elts;
    if (s->args.nelts != 1 || arg[0].len == 0) {
        return NGX_MAIL_PARSE_INVALID_COMMAND;
    }

    s->host.len = arg[0].len;
    s->host.data = ngx_pnalloc(c->pool, s->host.len);
    if (s->host.data == NULL) {
        return NGX_ERROR;
    }

    ngx_memcpy(s->host.data, arg[0].data, s->host.len);

    starttls_on = starttls_only = 0;

#if (NGX_MAIL_SSL)
    if (c->ssl == NULL) {
        ngx_mail_ssl_conf_t  *sslcf;

        sslcf = ngx_mail_get_module_srv_conf(s, ngx_mail_ssl_module);

        if (sslcf->starttls == NGX_MAIL_STARTTLS_ON) {
            starttls_on = 1;
        }

        if (sslcf->starttls == NGX_MAIL_STARTTLS_ONLY) {
            starttls_only = 1;
        }
    }
#endif

    if (ngx_mail_xmpp_id(s, c) != NGX_OK) {
        return NGX_ERROR;
    }

    xscf = ngx_mail_get_module_srv_conf(s, ngx_mail_xmpp_module);

    len = sizeof(xmpp_stream_header_from) - 1
        + s->host.len
        + sizeof(xmpp_stream_header_id) - 1
        + sizeof(xmpp_stream_header_features) - 1
        + sizeof(xmpp_stream_header_end) - 1
        + s->salt.len;

    if (starttls_on) {
        len += sizeof(xmpp_stream_feature_starttls) - 1;
    }
    else if (starttls_only) {
        len += sizeof(xmpp_stream_feature_starttls_required) - 1;
    }
    if (!starttls_only) {
        len += sizeof(xmpp_stream_feature_sasl_start) - 1
             + xscf->auth_mechanisms.len
             + sizeof(xmpp_stream_feature_sasl_end) - 1;
    }

    out = p = ngx_pnalloc(c->pool, len + 1);
    if (p == NULL) {
        return NGX_ERROR;
    }

    p = ngx_cpymem(p, xmpp_stream_header_from, sizeof(xmpp_stream_header_from) - 1);
    p = ngx_cpymem(p, s->host.data, s->host.len);
    p = ngx_cpymem(p, xmpp_stream_header_id, sizeof(xmpp_stream_header_id) - 1);
    p = ngx_cpymem(p, s->salt.data, s->salt.len);
    p = ngx_cpymem(p, xmpp_stream_header_features, sizeof(xmpp_stream_header_features) - 1);
    if (starttls_on) {
        p = ngx_cpymem(p, xmpp_stream_feature_starttls, sizeof(xmpp_stream_feature_starttls) - 1);
    }
    else if (starttls_only) {
        p = ngx_cpymem(p, xmpp_stream_feature_starttls_required, sizeof(xmpp_stream_feature_starttls_required) - 1);
    }
    if (!starttls_only) {
        p = ngx_cpymem(p, xmpp_stream_feature_sasl_start, sizeof(xmpp_stream_feature_sasl_start) - 1);
        p = ngx_cpymem(p, xscf->auth_mechanisms.data, xscf->auth_mechanisms.len);
        p = ngx_cpymem(p, xmpp_stream_feature_sasl_end, sizeof(xmpp_stream_feature_sasl_end) - 1);
    }
    p = ngx_cpymem(p, xmpp_stream_header_end, sizeof(xmpp_stream_header_end) - 1);
    *p = 0;

    s->out.data = out;
    s->out.len = len;

    s->mail_state = ngx_xmpp_stream;

    return NGX_OK;
}

static ngx_int_t
ngx_mail_xmpp_starttls(ngx_mail_session_t *s, ngx_connection_t *c)
{
#if (NGX_MAIL_SSL)
    ngx_mail_ssl_conf_t  *sslcf;

    if (s->mail_state != ngx_xmpp_stream) {
        return NGX_MAIL_PARSE_INVALID_COMMAND;
    }

    if (c->ssl == NULL) {
        sslcf = ngx_mail_get_module_srv_conf(s, ngx_mail_ssl_module);
        if (sslcf->starttls) {
            c->read->handler = ngx_mail_starttls_handler;
            ngx_str_set(&s->out, xmpp_starttls_proceed);
            s->mail_state = ngx_xmpp_start;
            return NGX_OK;
        }
    }
#endif

    return NGX_MAIL_PARSE_INVALID_COMMAND;
}

static ngx_int_t
ngx_mail_xmpp_auth(ngx_mail_session_t *s, ngx_connection_t *c)
{
    ngx_int_t                  rc;

#if (NGX_MAIL_SSL)
    if (ngx_mail_starttls_only(s, c)) {
        return NGX_MAIL_PARSE_INVALID_COMMAND;
    }
#endif

    rc = ngx_mail_auth_parse(s, c);

    switch (rc) {

    case NGX_MAIL_AUTH_LOGIN:

        ngx_str_set(&s->out, xmpp_auth_login_username_challenge);
        s->mail_state = ngx_xmpp_auth_login_username;

        return NGX_OK;

    case NGX_MAIL_AUTH_LOGIN_USERNAME:

        ngx_str_set(&s->out, xmpp_auth_login_password_challenge);
        s->mail_state = ngx_xmpp_auth_login_password;

        return ngx_mail_auth_login_username(s, c, 1);

    case NGX_MAIL_AUTH_PLAIN:

        ngx_str_set(&s->out, xmpp_auth_plain_challenge);
        s->mail_state = ngx_xmpp_auth_plain;

        return NGX_OK;

    }

    return rc;
}

void
ngx_mail_xmpp_auth_fixup(ngx_mail_session_t *s, ngx_connection_t *c)
{
    u_char *p, *login;
    size_t  len;

    len = s->login.len + s->host.len + 1;

    p = ngx_pnalloc(c->pool, len);
    if (p == NULL) {
        ngx_mail_session_internal_server_error(s);
        return;
    }

    login = p;

    p = ngx_cpymem(p, s->login.data, s->login.len);
    *p++ = '@';
    p = ngx_cpymem(p, s->host.data, s->host.len);

    s->login.data = login;
    s->login.len = len;
    s->host.len = 0;

    ngx_mail_auth(s, c);
}
