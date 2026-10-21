#!/bin/bash

mkdir -p certs
cd certs

PKI_DIR=../../strongswan/bin
PKI=${PKI_DIR}/pki

# generate CA private key, selfsigned certificate
echo "generating CA certificate..."
$PKI -g --type ecdsa --size 256 --outform pem > strongswanKey.pem
$PKI --self --ca --lifetime 3652 --in strongswanKey.pem \
    --dn "C=CH, O=strongSwan, CN=strongSwan Root CA" \
    --outform pem > strongswanCert.pem

# generate moon key, certificate
echo "generating moon certificate..."
$PKI --gen --type ecdsa --size 256 --outform pem > moonKey.pem
$PKI --req --type priv --in moonKey.pem \
    --dn "C=CH, O=strongswan, CN=moon.strongswan.org" \
    --san moon.strongswan.org --outform pem > moonReq.pem
$PKI --issue --cacert strongswanCert.pem --cakey strongswanKey.pem \
    --type pkcs10 --in moonReq.pem --serial 01 --lifetime 1826 \
    --outform pem > moonCert.pem

rm -rf moonReq.pem

# generate sun key, certificate
echo "generating sun certificate..."
$PKI --gen --type ecdsa --size 256 --outform pem > sunKey.pem
$PKI --req --type priv --in sunKey.pem \
    --dn "C=CH, O=strongswan, CN=sun.strongswan.org" \
    --san sun.strongswan.org --outform pem > sunReq.pem
$PKI --issue --cacert strongswanCert.pem --cakey strongswanKey.pem \
    --type pkcs10 --in sunReq.pem --serial 02 --lifetime 1826 \
    --outform pem > sunCert.pem

rm -rf sunReq.pem

# dump certificate
$PKI --print --in strongswanCert.pem
$PKI --print --in moonCert.pem
$PKI --print --in sunCert.pem

cd ..
