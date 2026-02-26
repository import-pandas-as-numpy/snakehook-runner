from snakehook_runner.core.rate_limit import FixedWindowRateLimiter


def test_fixed_window_rate_limiter() -> None:
    limiter = FixedWindowRateLimiter(limit=2, window_sec=10)

    assert limiter.allow("1.2.3.4", now=100.0)
    assert limiter.allow("1.2.3.4", now=101.0)
    assert not limiter.allow("1.2.3.4", now=102.0)
    assert limiter.allow("1.2.3.4", now=111.0)
