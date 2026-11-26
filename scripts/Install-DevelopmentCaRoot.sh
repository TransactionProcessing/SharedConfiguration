#!/usr/bin/env bash
set -euo pipefail

usage() {
  echo "Usage: sudo $0 <root-ca.crt> <expected-sha256-fingerprint>" >&2
}

if [[ $# -ne 2 ]]; then usage; exit 2; fi
root_cert=$1
expected=${2//:/}
if [[ ! -f "$root_cert" ]]; then echo "Root certificate not found: $root_cert" >&2; exit 1; fi
if [[ ! "$expected" =~ ^[[:xdigit:]]{64}$ ]]; then echo "Expected fingerprint must be 64 hexadecimal SHA-256 characters." >&2; exit 2; fi

actual=$(openssl x509 -in "$root_cert" -outform DER | sha256sum | awk '{print toupper($1)}')
expected=${expected^^}
if [[ "$actual" != "$expected" ]]; then
  echo "Root certificate fingerprint mismatch. Expected $expected; received $actual. Nothing installed." >&2
  exit 1
fi
if ! openssl x509 -in "$root_cert" -noout -text | grep -q 'CA:TRUE'; then
  echo "The fingerprint matched, but the supplied certificate is not marked as a CA certificate." >&2
  exit 1
fi

destination=/usr/local/share/ca-certificates/transactionprocessing-development-ca.crt
if [[ -f "$destination" ]] && cmp -s "$root_cert" "$destination"; then
  echo "Verified development CA root is already installed."
  exit 0
fi

install -D -m 0644 "$root_cert" "$destination"
update-ca-certificates
echo "Installed verified development CA root (SHA-256 $actual)."
