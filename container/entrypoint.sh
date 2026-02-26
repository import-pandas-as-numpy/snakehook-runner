#!/usr/bin/env bash
set -euo pipefail

: "${API_TOKEN:?API_TOKEN is required}"
: "${DISCORD_WEBHOOK_URL:?DISCORD_WEBHOOK_URL is required}"

python - <<'PY'
import os
from snakehook_runner.infra.nftables_renderer import build_dns_resolver_allowlist, write_rules_file

raw = os.getenv("DNS_RESOLVERS", "1.1.1.1,8.8.8.8")
dns_resolvers = build_dns_resolver_allowlist(raw=raw)
write_rules_file(os.environ["DISCORD_WEBHOOK_URL"], "/tmp/snakehook.nft", dns_resolvers)
PY

nft -f /tmp/snakehook.nft
exec uvicorn snakehook_runner.main:create_app --factory --host 0.0.0.0 --port 8080
