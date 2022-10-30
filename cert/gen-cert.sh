#!/bin/bash

set -xe

work_dir=$(cd $(dirname $0); pwd)
dir='dev'

if [ $# -eq 1 ]; then
  while getopts ":r" opt
  do
    case $opt in
        r)
        dir='release'
        ;;
        ?)
        echo "Unknow input"
        exit 1
        ;;
    esac
  done
fi

dir=$work_dir/$dir

rm -rf $dir
mkdir $dir

openssl req -nodes \
          -x509 \
          -days 3650 \
          -newkey rsa:4096 \
          -keyout $dir/ca.key \
          -out $dir/ca.cert \
          -sha256 \
          -batch \
          -subj "/CN=ponytown RSA CA"

openssl req -nodes \
          -newkey rsa:2048 \
          -keyout $dir/server.key \
          -out $dir/server.req \
          -sha256 \
          -batch \
          -subj "/CN=testserver.com"

openssl rsa \
          -in $dir/server.key \
          -out $dir/server.rsa

openssl req -nodes \
          -newkey rsa:2048 \
          -keyout $dir/client.key \
          -out $dir/client.req \
          -sha256 \
          -batch \
          -subj "/CN=ponytown client"

for kt in $dir ; do
  openssl x509 -req \
            -in $kt/server.req \
            -out $kt/server.cert \
            -CA $kt/ca.cert \
            -CAkey $kt/ca.key \
            -sha256 \
            -days 2000 \
            -set_serial 456 \
            -extensions v3_server -extfile openssl.cnf

  openssl x509 -req \
            -in $kt/client.req \
            -out $kt/client.cert \
            -CA $kt/ca.cert \
            -CAkey $kt/ca.key \
            -sha256 \
            -days 2000 \
            -set_serial 789 \
            -extensions v3_client -extfile openssl.cnf

  cat $kt/server.cert $kt/ca.cert > $kt/server.fullchain
done

rm $dir/*.req
rm $dir/ca.key
rm $dir/server.cert $dir/server.key
