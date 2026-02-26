from __future__ import annotations

import hmac


def is_valid_bearer(auth_header: str | None, expected_token: str) -> bool:
    if not auth_header:
        return False
    prefix = "Bearer "
    if not auth_header.startswith(prefix):
        return False
    token = auth_header[len(prefix) :]
    return hmac.compare_digest(token, expected_token)
