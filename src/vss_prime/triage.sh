#!/bin/sh
set -e

# Splits the chain into cert.pem/chain.pem/fullchain.pem under
# certs/live/<cn>, paired with the privkey.pem that's been sitting in
# certs/enroll/<cn> the whole time. Prefers issued.p7b (certreq's own
# CertChainFileOut, a proper PKCS7 bundle certreq built for us) when
# present -- no need to guess whether issued.cer (CertFileOut, meant to
# be just the leaf) happens to be a bundle too; falls back to that
# guess only for older staged data that predates asking certreq for
# the chain directly.

CN="$1"
ENROLL_DIR="/opt/vertigis-studio/certs/enroll/$CN"
LIVE_DIR="/opt/vertigis-studio/certs/live/$CN"
STAGED="$ENROLL_DIR/issued.cer"
STAGED_CHAIN="$ENROLL_DIR/issued.p7b"
BUNDLE="$ENROLL_DIR/.bundle.pem"

mkdir -p "$LIVE_DIR"

if [ -s "$STAGED_CHAIN" ] && openssl pkcs7 -in "$STAGED_CHAIN" -print_certs -out "$BUNDLE" 2>/dev/null; then
    :
elif ! openssl pkcs7 -in "$STAGED" -print_certs -out "$BUNDLE" 2>/dev/null; then
    cp "$STAGED" "$BUNDLE"
fi

# -print_certs also emits human-readable "subject=.../issuer=..." lines
# before each cert -- strip them (keep only the BEGIN..END PEM blocks
# themselves), otherwise the per-cert split below attributes each such
# line to the *previous* cert's output file (it hasn't seen that cert's
# own BEGIN marker yet), leaking cosmetic text into the wrong file.
# Harmless to any real PEM consumer, but sloppy and worth not shipping.
awk '/-----BEGIN CERTIFICATE-----/,/-----END CERTIFICATE-----/' "$BUNDLE" > "$BUNDLE.clean"
mv "$BUNDLE.clean" "$BUNDLE"

rm -f "$ENROLL_DIR"/.cert-*.pem
awk -v dir="$ENROLL_DIR" '
    /-----BEGIN CERTIFICATE-----/ { n++ }
    { print > (dir "/.cert-" n ".pem") }
' "$BUNDLE"

cp "$ENROLL_DIR/.cert-1.pem" "$LIVE_DIR/cert.pem"

: > "$LIVE_DIR/chain.pem"
for f in "$ENROLL_DIR"/.cert-*.pem; do
    [ "$f" = "$ENROLL_DIR/.cert-1.pem" ] && continue
    cat "$f" >> "$LIVE_DIR/chain.pem"
done

cp "$BUNDLE" "$LIVE_DIR/fullchain.pem"
cp "$ENROLL_DIR/privkey.pem" "$LIVE_DIR/privkey.pem"

rm -f "$ENROLL_DIR"/.cert-*.pem "$BUNDLE"
