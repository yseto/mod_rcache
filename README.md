mod_rcache
==========

- hiredis (https://github.com/redis/hiredis)
- apache 2.4.10

````
apxs -cia mod_rcache.c  -lcurl -lhiredis
````

````
RewriteEngine On

<IfModule rcache_module>
RedisHostname localhost
RedisPort 6379
</IfModule>

<Location "/foo/">
SetHandler rcache
</Location>

RewriteRule ^/(.*)$ /foo/$1 [E=ENVTEST:http://$1,PT]
````

````
curl http://localhost:8080/foo.baa.example/ -LI
````

