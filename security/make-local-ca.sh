#!/bin/bash
#
# Generates a local development CA and a leaf certificate for
# localhost signed by that CA. Run once; import local-ca.crt into
# your browser's authority store and your browser will fully trust
# any cert the CA signs.
#
# Output files (in this directory):
#   local-ca.key   - CA private key (keep secret, .gitignore-friendly)
#   local-ca.crt   - CA root cert; import this into your browser
#   localhost.key  - server private key for atto to use
#   localhost.crt  - server leaf cert signed by local-ca
#
# Usage:
#   cd security/
#   ./make-local-ca.sh
#
# Then in your atto example, point local_cert at localhost.crt
# and local_pk at localhost.key (instead of the self-signed
# server.crt / server.key which most other examples still use).
#
# Why this exists:
# - server.crt is a self-signed leaf cert. Browsers let you
#   "Accept the Risk and Continue" past it, but won't import it
#   as a Certificate Authority and won't promote H2 connections
#   to H3 via Alt-Svc against it.
# - A locally-signed CA cert that you import into your browser
#   trust store fixes both: the browser trusts the leaf cert
#   without warnings AND will race H3 connections.

set -euo pipefail

cd "$(dirname "$0")"

if ! command -v openssl >/dev/null 2>&1; then
    echo "error: openssl not found in PATH" >&2
    exit 1
fi

if [ -f local-ca.crt ] && [ -f localhost.crt ]; then
    echo "local-ca.crt and localhost.crt already exist."
    echo "Delete them first if you want to regenerate."
    exit 0
fi

echo "Generating Atto local development CA..."
openssl genrsa -out local-ca.key 4096 2>/dev/null
openssl req -x509 -new -nodes \
    -key local-ca.key \
    -sha256 -days 3650 \
    -config local-ca.cnf \
    -out local-ca.crt 2>/dev/null
echo "  wrote local-ca.key, local-ca.crt"

echo "Generating localhost leaf cert..."
openssl genrsa -out localhost.key 2048 2>/dev/null
openssl req -new \
    -key localhost.key \
    -config localhost.cnf \
    -out localhost.csr 2>/dev/null

# Sign the leaf with the CA. The -extfile + -extensions pair
# carries the SAN and constraint extensions over from the leaf
# config; without -copy_extensions, openssl x509 strips them
# silently (which is why a hand-rolled CSR signing without these
# flags produces a useless cert with no SAN).
openssl x509 -req -in localhost.csr \
    -CA local-ca.crt -CAkey local-ca.key -CAcreateserial \
    -out localhost.crt \
    -days 825 -sha256 \
    -extfile localhost.cnf -extensions v3_req 2>/dev/null
rm -f localhost.csr local-ca.srl
echo "  wrote localhost.key, localhost.crt"

echo ""
echo "Done. Next steps:"
echo ""
echo "  1. Import local-ca.crt into your browser's authority store:"
echo ""
echo "     Firefox:"
echo "       Settings -> Privacy & Security -> Certificates ->"
echo "       View Certificates -> Authorities -> Import"
echo "       Select local-ca.crt and check"
echo "       'Trust this CA to identify websites'"
echo ""
echo "     Safari (macOS):"
echo "       Open Keychain Access -> drop local-ca.crt onto"
echo "       'login' or 'System' keychain -> right-click ->"
echo "       Get Info -> Trust -> 'Always Trust' for SSL"
echo ""
echo "     Chrome / Edge:"
echo "       On macOS uses the Keychain Access steps above."
echo "       On Linux: certutil -d sql:\$HOME/.pki/nssdb -A -t"
echo "         'CT,c,c' -n 'Atto Local Development CA' -i local-ca.crt"
echo ""
echo "  2. Point your atto example at the new cert:"
echo "     'local_cert' => __DIR__ . '/../../security/localhost.crt'"
echo "     'local_pk'   => __DIR__ . '/../../security/localhost.key'"
echo ""
echo "  3. Restart atto and reload your page; H1/H2/H3 will all"
echo "     be fully trusted and Alt-Svc will work."
