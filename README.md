# nginx-xmpp

This is [nginx](http://nginx.org/en/) with [XMPP](https://tools.ietf.org/html/rfc6120) proxy support. It adds XMPP to the list of protocols supported by the mail module, allowing nginx to do TLS and auth termination for XMPP servers.

Its assumed you know how to use nginx's [mail module](http://nginx.org/en/docs/mail/ngx_mail_core_module.html). XMPP support will be built with the `--with-mail` switch to `configure`. Use `protocol xmpp;` in your server config to enable XMPP on a port.

## To do

- [ ] federation/S2S
- [ ] multiple certificate support (like SNI but using domain from stream header)
- [ ] XEP-0198 session resumption?
- [ ] CRAM-MD5?
- [ ] ...

## Further reading

http://robn.io/nginx-xmpp/ has the history and rationale for this project.

## Shameless advertising

[FastMail](https://www.fastmail.com/) employs me to do crazy things like this :)
