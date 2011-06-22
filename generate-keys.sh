#!/usr/bin/env bash

#Generate a new unencrypted rsa private key in PEM format
openssl genrsa -out client.key 1024

#Create a certificate signing request (CSR) using your rsa private key
openssl req -new -key client.key -out client.csr

#Self-sign your CSR with your own private key
openssl x509 -req -days 365 -in client.csr -CA /etc/apache2/ssl/ca.crt -CAkey ../server.key -set_serial 01 -out client.crt
#openssl x509 -req -days 3650 -in client.csr -signkey server.pem -out client.pem

# generate a pkcs12 key
openssl pkcs12 -export -out client.p12 -inkey client.key -in client.crt

cat client.key client.crt > client.pem