#!/bin/bash

if [ ! -f mach5.p12 ]; then
  keytool -genkeypair \
          -alias mach5_root \
          -dname "cn=mach5 root, o=mach5, c=US" \
          -keyalg EC \
          -groupname secp256r1 \
          -sigalg SHA256withECDSA \
          -storetype pkcs12 \
          -keystore mach5.p12 \
          -storepass password \
          -keypass password \
          -validity 3650 \
          -ext BasicConstraints:critical=ca:true \
          -ext KeyUsage:critical=keyCertSign,cRLSign

  keytool -exportcert -alias mach5_root -file mach5_root.crt -keystore mach5.p12 -storepass password
  openssl x509 -in mach5_root.crt -out mach5_root.pem -outform PEM

  cp -f mach5.p12 ../app/src/main/resources/
fi
