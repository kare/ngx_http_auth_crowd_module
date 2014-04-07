#!/bin/sh
sudo apt-get install libpcre3-dev build-essential libssl-dev libcurl4-openssl-dev
curl -O http://nginx.org/download/nginx-1.5.9.tar.gz
tar xzvf nginx-1.5.9.tar.gz
cd nginx-1.5.9
./configure --add-module=.. --conf-path=/home/kare/ngx_http_auth_crowd_module/conf/nginx.conf --with-debug --with-http_ssl_module
make
