from functools import wraps


def otp_exempt(view_func):
    """Mark a view function as exempt from OTP verification."""

    @wraps(view_func)
    def wrapped_view(*args, **kwargs):
        return view_func(*args, **kwargs)

    wrapped_view.otp_exempt = True
    return wrapped_view
