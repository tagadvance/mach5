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
  openssl pkcs12 -in mach5.p12 -nocerts -nodes -out mach5_root.key

  # generate keypair and csr
  keytool -genkeypair -alias mach5 -keyalg EC -groupname secp256r1 -sigalg SHA256withECDSA -keystore mach5.p12 -storepass password -keypass password -ext san=dns:mach5.example.com
  keytool -certreq -alias mach5 -file mach5.csr -keystore mach5.p12 -storepass password -keypass password
  # generate a signed certificate for the associated Certificate Signing Request.
  openssl x509 -req -CA mach5_root.pem -CAkey mach5_root.key -in mach5.csr -out mach5.cer -days 3650 -CAcreateserial
  # copy cert to pem
  openssl x509 -in mach5.cer -out mach5.pem -outform PEM
  # verify
  openssl verify -CAfile mach5_root.pem mach5.pem
  # import
  keytool -importcert -alias mach5 -file mach5.cer -keystore mach5.p12 -storepass password -keypass password

  cp -f mach5.p12 ../app/src/main/resources/
fi

if [ -f mach5.p12 ]; then
#  sudo mkdir -p /usr/local/share/ca-certificates/mach5
#  keytool -export -keystore mach5.p12 -storepass password -alias mach5_root -file mach5_root.crt
#  sudo cp mach5_root.crt /usr/local/share/ca-certificates/mach5/
#  rm -f mach5_root.crt
#  sudo update-ca-certificates
#
#  keytool -export -rfc -keystore mach5.p12 -storepass password -alias mach5_root -file mach5_root.pem

#  # export ca private key
#  openssl pkcs12 -in mach5.p12 -nodes -nocerts -out ca_private_key.pem
#  # generate keypair and csr
#  keytool -genkeypair -alias mach5 -keyalg RSA -keysize 2048 -keystore mach5.p12 -storepass password -keypass password -dname "CN=mach5.example.com"
#  keytool -certreq -alias mach5 -file mach5.csr -keystore mach5.p12 -storepass password -keypass password
#  # sign csr with ca private key
#  openssl x509 -req -in mach5.csr -CA mach5_root.pem -CAkey ca_private_key.pem -CAcreateserial -out mach5.cer -days 365
#  # import certificate
#  keytool -importcert -alias mach5_example_com -file mach5.cer -keystore mach5.p12 -storepass password
#
#  cp -f mach5.p12 ../app/src/main/resources/
fi
