#!/bin/bash

set -x

kubectl create secret tls tls-cert-spoink --cert spoink-fullchain.pem --key spoink-privkey.pem
kubectl create secret tls tls-cert-woeby --cert woeby-fullchain.pem --key woeby-privkey.pem
kubectl create secret tls tls-cert-blackbox --cert blackbox-fullchain.pem --key blackbox-privkey.pem
