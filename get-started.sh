#!/bin/sh
NGINX_VERSION=$1
DIR=$(pwd)
cd ..
if [[ "$2" == '-i' ]]; then
  if [ -f "/etc/redhat-release" ]; then
    sudo yum install gc gcc gcc-c++ pcre-devel zlib-devel make wget openssl-devel libxml2-devel libcurl
  else
    sudo apt-get install libpcre3-dev build-essential libssl-dev libcurl4-openssl-dev
  fi
fi
curl -O http://nginx.org/download/nginx-$NGINX_VERSION.tar.gz
tar xzvf nginx-$NGINX_VERSION.tar.gz
if [ -d "nginx" ]; then
  rm nginx
fi
mv nginx-$NGINX_VERSION nginx
rm nginx-$NGINX_VERSION.tar.gz
cd nginx
./configure  --prefix=/etc/nginx --sbin-path=/usr/sbin/nginx --conf-path=/etc/nginx/nginx.conf --error-log-path=/var/log/nginx/error.log --http-log-path=/var/log/nginx/access.log --pid-path=/var/run/nginx.pid --lock-path=/var/run/nginx.lock --http-client-body-temp-path=/var/cache/nginx/client_temp --http-proxy-temp-path=/var/cache/nginx/proxy_temp --http-fastcgi-temp-path=/var/cache/nginx/fastcgi_temp --http-uwsgi-temp-path=/var/cache/nginx/uwsgi_temp --http-scgi-temp-path=/var/cache/nginx/scgi_temp --user=nginx --group=nginx --with-http_ssl_module --with-http_realip_module --with-http_addition_module --with-http_sub_module --with-http_dav_module --with-http_flv_module --with-http_mp4_module --with-http_gunzip_module --with-http_gzip_static_module --with-http_random_index_module --with-http_secure_link_module --with-http_stub_status_module --with-http_auth_request_module --with-threads --with-stream --with-stream_ssl_module --with-http_slice_module --with-mail --with-mail_ssl_module --with-file-aio --with-http_v2_module --with-ipv6 --add-dynamic-module=$DIR --with-ld-opt="-lcurl"
make modules
