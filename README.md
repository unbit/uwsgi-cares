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

caching
=======

You can force the c-ares resolver to cache results in uWSGI caches

```ini
[uwsgi]
plugins = cares,router_http
; create a cache named mydnscache able to contains 1000 items of 1k size
cache2 = name=mydnscache,items=1000,blocksize=1024
; tell c-ares to cache results in mydnscache
cares-cache = mydnscache
; do not cache results for more than 60 seconds
cares-cache-ttl = 60
route-run = http:${dns[HTTP_HOST]}:${SERVER_PORT}
```

options
=======

`cares-cache` cache every c-ares query in the specified uWSGI cache

`cares-cache-ttl` force the ttl when caching dns query results

`cares-resolve` place the result of a dns query in the specified placeholder, sytax: placeholder=name (immediate option)
