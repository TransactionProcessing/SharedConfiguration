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

temporary_directory=$(mktemp -d)
trap 'rm -rf "$temporary_directory"' EXIT
verified_root="$temporary_directory/root-ca.crt"
# Parse and serialize only the first certificate. Never install additional PEM
# certificates that may have been appended to the input file.
openssl x509 -in "$root_cert" -outform PEM -out "$verified_root"
actual=$(openssl x509 -in "$verified_root" -outform DER | sha256sum | awk '{print toupper($1)}')
expected=${expected^^}
if [[ "$actual" != "$expected" ]]; then
  echo "Root certificate fingerprint mismatch. Expected $expected; received $actual. Nothing installed." >&2
  exit 1
fi
if ! openssl x509 -in "$verified_root" -noout -text | grep -q 'CA:TRUE'; then
  echo "The fingerprint matched, but the supplied certificate is not marked as a CA certificate." >&2
  exit 1
fi

destination=/usr/local/share/ca-certificates/transactionprocessing-development-ca.crt
if [[ -f "$destination" ]] && cmp -s "$verified_root" "$destination"; then
  echo "Verified development CA root is already installed."
  exit 0
fi

install -D -m 0644 "$verified_root" "$destination"
update-ca-certificates
echo "Installed verified development CA root (SHA-256 $actual)."
