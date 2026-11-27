#!/usr/bin/env bash
set -euo pipefail

if [[ $# -ne 1 ]]; then
  echo "Usage: $0 https://<server-ip-or-dns>:<port>/<optional-path>" >&2
  exit 2
fi
url=$1
if [[ "$url" != https://* ]]; then echo "URL must use HTTPS." >&2; exit 2; fi
if ! command -v curl >/dev/null 2>&1; then echo "curl is required." >&2; exit 1; fi

echo "Checking HTTPS with the operating system trust store: $url"
# Deliberately do not pass --insecure/-k. A non-2xx HTTP response is still a
# successful TLS validation, so report the status without making it fatal.
curl --silent --show-error --output /dev/null --write-out 'PASS: TLS validation succeeded; HTTP %{http_code}\n' "$url"
