from django_ratelimit.decorators import ratelimit

_default_rate_limits = [
    ratelimit(key="ip", method=ratelimit.UNSAFE, rate="10/s"),
    ratelimit(key="ip", method=ratelimit.UNSAFE, rate="30/m"),
]


def _apply_rate_limits(*rate_limits, view):
    for rate_limit in rate_limits:
        view = rate_limit(view)
    return view


def rate_limit_default(view):
    return _apply_rate_limits(*_default_rate_limits, view=view)


def rate_limit_strict(view):
    return _apply_rate_limits(
        *_default_rate_limits,
        ratelimit(key="ip", method=ratelimit.ALL, rate="100/15m"),
        view=view,
    )
