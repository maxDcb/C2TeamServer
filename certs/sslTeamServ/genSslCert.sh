#! /bin/bash

# https://github.com/joekottke/python-grpc-ssl

# Generate CA Certificate and Config
cfssl gencert -initca ca-csr.json | cfssljson -bare ca

# Server Certificate
cfssl gencert -ca=ca.pem -ca-key=ca-key.pem -config=ca-config.json -hostname='127.0.0.1,localhost' server-csr.json | cfssljson -bare server

# Client Certificate
cfssl gencert -ca=ca.pem -ca-key=ca-key.pem -config=ca-config.json client-csr.json | cfssljson -bare client