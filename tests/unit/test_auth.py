from snakehook_runner.core.auth import is_valid_bearer


def test_auth_rejects_wrong_prefix() -> None:
    assert is_valid_bearer("Token abc", "abc") is False


def test_auth_accepts_matching_bearer_token() -> None:
    assert is_valid_bearer("Bearer abc", "abc") is True


def test_auth_rejects_non_matching_bearer_token() -> None:
    assert is_valid_bearer("Bearer wrong", "abc") is False
