#!/bin/bash
keytool -genkeypair \
    -alias crypto-server \
    -keyalg RSA -keysize 2048 \
    -storetype PKCS12 \
    -keystore src/main/resources/keystore.p12 \
    -storepass changeit \
    -validity 365 \
    -dname "CN=localhost, OU=Dev, O=Crypto, C=PT" \
    -ext "SAN=dns:localhost,ip:127.0.0.1"

keytool -exportcert \
    -alias crypto-server \
    -keystore src/main/resources/keystore.p12 \
    -storepass changeit \
    -file src/main/resources/server-cert.cer \
    -rfc

keytool -importcert \
    -alias crypto-server \
    -file src/main/resources/server-cert.cer \
    -keystore src/main/resources/truststore.p12 \
    -storepass changeit \
    -storetype PKCS12 \
    -noprompt

echo "✅ TLS configurado com sucesso!"
