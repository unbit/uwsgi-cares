uwsgi-cares
===========

uWSGI plugin for integration with the c-ares async dns library

installation
============

the plugin is 2.x friendly

```sh
uwsgi --build-plugin https://github.com/unbit/uwsgi-cares
```

usage
=====

The plugin exposes various features aimed at async/non-blocking dns resolving

You can use in the internal routing framework to resolve request var value:

```ini
[uwsgi]
plugins = cares,router_http
route-run = http:${dns[HTTP_HOST]}:${SERVER_PORT}
```

the dns[] route_var is smart in the presence of colon. This avoid you to split ports in addr:port strings

Another usage is mapping a resolution to a placeholder

```ini
[uwsgi]
plugins = cares
cares-resolve = mysubscriptionserver=myrouter.foo
subscribe2 = server=%(mysubscriptionserver):9999,key=foo.bar
...
```
