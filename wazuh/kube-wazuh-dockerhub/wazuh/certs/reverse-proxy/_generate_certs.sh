#!/bin/bash

DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" >/dev/null 2>&1 && pwd )"
cd $DIR

echo "Root CA"

openssl genrsa -out root-ca-key.pem 2048

openssl req -days 3650 -new -x509 -sha256 -key root-ca-key.pem -out root-ca.pem -subj "/C=US/L=California/O=Company/CN=root-ca"




echo "* ext cert"

echo "create: node-key-temp.pem"

openssl genrsa -out node-key-temp.pem 2048

echo "create: node-key.pem"

openssl pkcs8 -inform PEM -outform PEM -in node-key-temp.pem -topk8 -nocrypt -v1 PBE-SHA1-3DES -out node-key.pem

echo "create: node.csr"

openssl req -days 3650 -new -key node-key.pem -out node.csr -subj "/C=US/L=California/O=Company/CN=wazuh" -reqexts SAN -config <(cat /etc/ssl/openssl.cnf <(printf "\n[SAN]\nsubjectAltName=DNS:wazuh.kube.local\n"))

echo "create: node.pem"

openssl x509 -req -days 3650 -in node.csr -CA root-ca.pem -CAkey root-ca-key.pem -CAcreateserial -sha256 -out node.pem

mv ./node-key.pem ./cert-ext.key
mv ./node.pem ./cert-ext.pem
mv ./root-ca-key.pem ./root-ca.key
mv ./root-ca.pem ./root-ca.pem

rm *.csr
rm *-temp.pem
