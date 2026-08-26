#!/usr/bin/env bash
#
# Produces the root CA mach5 signs its minted leaves with: a certificate and a
# private key, both PEM, which is what `[ca] cert` and `[ca] key` want.
#
# If mach5.p12 is here — the keystore the Java prototype generated — the root is
# exported from it rather than replaced, so any device that already trusts that
# root keeps working. Otherwise a new EC root is generated.
#
# Nothing here is overwritten. Delete the outputs yourself if you mean to start
# again, and remember that every device trusting the old root stops working the
# moment you do.

set -euo pipefail

cd "$(dirname "$0")"

cert=${MACH5_CA_CERT:-mach5_root_cert.pem}
key=${MACH5_CA_KEY:-mach5_root_key.pem}
keystore=${MACH5_CA_KEYSTORE:-mach5.p12}
days=${MACH5_CA_DAYS:-3650}

# Whose root this is. It ends up in the certificate every device that trusts
# this proxy will show, so it should say something true about *you* — this is
# your certificate authority, not anybody else's.
#
#   MACH5_CA_SUBJECT="/CN=my mach5 root/O=My Homelab/C=GB" bash security/init.sh
#
# The default deliberately names nobody.
subject=${MACH5_CA_SUBJECT:-/CN=mach5 root/O=mach5}

if [[ -f $cert && -f $key ]]; then
	echo "already present: $cert and $key"
	openssl x509 -in "$cert" -noout -subject -dates
	exit 0
fi

if [[ -f $keystore ]]; then
	echo "exporting the existing root from $keystore"
	# A migration path for one keystore that was never shared, and nothing else:
	# the prototype that generated it hardcoded this password, so it is written
	# here rather than pretended about. Override it if yours differs; -passin
	# fails loudly rather than silently producing an empty key.
	password=${MACH5_CA_KEYSTORE_PASSWORD:-password}
	# Piped through x509/pkey to drop the "Bag Attributes" preamble openssl
	# writes ahead of the PEM block, which strict parsers refuse.
	openssl pkcs12 -in "$keystore" -passin "pass:$password" -nokeys \
		| openssl x509 -out "$cert"
	# Through SEC1 and back into PKCS#8, which is not a detour: keytool writes a
	# PKCS#8 EC key with no public-key point, and rcgen refuses those. SEC1
	# carries the point, so the round trip is what puts it back.
	openssl pkcs12 -in "$keystore" -passin "pass:$password" -nocerts -noenc \
		| openssl ec \
		| openssl pkcs8 -topk8 -nocrypt -out "$key"
else
	echo "generating a new EC root"
	openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 \
		-days "$days" -noenc -subj "$subject" \
		-addext "basicConstraints=critical,CA:TRUE" \
		-addext "keyUsage=critical,keyCertSign,cRLSign" \
		-keyout "$key" -out "$cert"
fi

# The private key is the whole of the proxy's authority over every device that
# trusts it. Both files are gitignored; this makes sure the key is not readable
# by anyone else on the box either.
chmod 600 "$key"
chmod 644 "$cert"

echo
openssl x509 -in "$cert" -noout -subject -dates
echo
echo "Point mach5 at them:"
echo
echo "  [ca]"
echo "  cert = \"security/$cert\""
echo "  key = \"security/$key\""
echo
echo "Then install the certificate on each device — mach5 serves it at"
echo "/.mach5/ca once it is running."
