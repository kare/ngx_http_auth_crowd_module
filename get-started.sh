#!/bin/sh
NGINX_VERSION=1.11.1
DIR=$(pwd)
cd ..
if [ -f "/etc/redhat-release" ]; then
    yum install gc gcc gcc-c++ pcre-devel zlib-devel make wget openssl-devel libxml2-devel libcurl
else
    apt-get install libpcre3-dev build-essential libssl-dev libcurl4-openssl-dev
fi
curl -O http://nginx.org/download/nginx-$NGINX_VERSION.tar.gz
tar xzvf nginx-$NGINX_VERSION.tar.gz
mv nginx-$NGINX_VERSION nginx
rm nginx-$NGINX_VERSION.tar.gz
cd nginx
./configure --with-http_ssl_module --add-dynamic-module=$DIR --with-ld-opt="-lcurl"
make modules
