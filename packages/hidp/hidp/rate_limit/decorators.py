from django_ratelimit.decorators import ratelimit

_DEFAULT_RATE_LIMITS = [
    ("ip", ratelimit.UNSAFE, "10/s"),
    ("ip", ratelimit.UNSAFE, "30/m"),
]

_STRICT_RATE_LIMITS = [
    *_DEFAULT_RATE_LIMITS,
    ("ip", ratelimit.ALL, "100/15m"),
]


def _view_class_group(view):
    """
    Name the rate limit group after the class of a class-based view.

    Views that guard the same secret can share a budget by setting the same
    `rate_limit_group` class attribute.
    """
    # method_decorator passes a partial of the bound method, on every request.
    instance = getattr(getattr(view, "func", None), "__self__", None)
    view_class = getattr(view, "view_class", None) or (
        type(instance) if instance is not None else None
    )
    if view_class is None:
        return None
    return getattr(view_class, "rate_limit_group", None) or (
        f"{view_class.__module__}.{view_class.__qualname__}"
    )


def _apply_rate_limits(rate_limits, view, *, block=True):
    group = _view_class_group(view)
    for key, method, rate in rate_limits:
        view = ratelimit(group=group, key=key, method=method, rate=rate, block=block)(
            view
        )
    return view


def rate_limit_default(view):
    return _apply_rate_limits(_DEFAULT_RATE_LIMITS, view)


def rate_limit_strict(view):
    return _apply_rate_limits(_STRICT_RATE_LIMITS, view)


def rate_limit(*, key, rate, method=ratelimit.ALL, block=True):
    """
    Apply one rate limit, counted per view class like the default limits.

    With `block=False` an exceeded limit sets `request.limited` instead of
    refusing the request.
    """
    return lambda view: _apply_rate_limits([(key, method, rate)], view, block=block)
