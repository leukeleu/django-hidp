from django.contrib import auth as django_auth


def authenticate(request, **credentials):
    """
    Attempts to authenticate (but **not** log in) a user using all configured
    authentication backends (`settings.AUTHENTICATION_BACKENDS`) with the
    provided credentials.

    Iterates over each backend until it finds one that accepts the credentials,
    leading to three possible outcomes:

    1. `None` is returned:
       The backend could not verify the credentials. The credentials may be
       invalid, or the backend is unable to produce a user for some other reason.

    2. A `User` object is returned:
       The credentials are valid and the user is allowed to log in.

    3. `PermissionDenied` is raised:
       The backend was able to verify the credentials, but the user is not
       allowed to log in.

    In the first scenario, the next backend is tried. In the other two
    scenarios, the iteration is stopped.

    Returns the authenticated user, annotated with the path of the backend that
    authenticated the user as `user.backend`, if successful.

    Returns `None` if the credentials are invalid, or access is denied,
    and sends the `django.contrib.auth.user_login_failed` signal.
    """

    # Wrap Django's authenticate, without altering its behavior, to add
    # a detailed docstring and provide a consistent interface for the
    # `hidp.accounts.auth` module.
    return django_auth.authenticate(request=request, **credentials)
