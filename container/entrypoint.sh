#!/usr/bin/env bash
set -euo pipefail

: "${API_TOKEN:?API_TOKEN is required}"
: "${DISCORD_WEBHOOK_URL:?DISCORD_WEBHOOK_URL is required}"

python - <<'PY'
from ipaddress import ip_address
from snakehook_runner.infra.nftables_renderer import write_rules_file
import os

raw = os.getenv("DNS_RESOLVERS", "1.1.1.1,8.8.8.8")
dns_resolvers: list[str] = []
for part in raw.split(","):
    value = part.strip()
    if not value:
        continue
    parsed = ip_address(value)
    if parsed.version != 4:
        raise ValueError("DNS_RESOLVERS currently supports IPv4 addresses only")
    dns_resolvers.append(value)
if not dns_resolvers:
    raise ValueError("DNS_RESOLVERS must contain at least one IP")
write_rules_file(os.environ["DISCORD_WEBHOOK_URL"], "/tmp/snakehook.nft", dns_resolvers)
PY

nft -f /tmp/snakehook.nft
exec uvicorn snakehook_runner.main:create_app --factory --host 0.0.0.0 --port 8080
