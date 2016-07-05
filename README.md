# Nginx http auth crowd module

## Configure and compile Nginx

```bash
$ ./configure --add-dynamic-module=../ngx_http_auth_crowd_module --with-debug --with-http_ssl_module
$ make modules
```
http://wiki.nginx.org/HttpSslModule

## Configuration example

```
server {
    location /restricted {
        auth_crowd              "Restricted Zone Realm";
        auth_crowd_url          "https://crowd.server.address.fi/crowd";
        auth_crowd_service      "crowd-authenticator-username";
        auth_crowd_password     "secret";
    }
}
```
### Development
 See [get-started.sh](https://github.com/kare/ngx_http_auth_crowd_module/blob/master/get-started.sh) for details.
### Developer Links
 * [Emiller's Guide To Nginx Module
         Development](http://www.evanmiller.org/nginx-modules-guide.html)
