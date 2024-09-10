from django.contrib import auth as django_auth
from django.contrib.auth.base_user import AbstractBaseUser


def authenticate(request, **credentials):
    """
    Attempts to authenticate a user using all configured authentication backends.

    Note that this does **not** log the user in. It only verifies the credentials.

    Iterates over each backend in `settings.AUTHENTICATION_BACKENDS` until it finds
    one that accepts the credentials, leading to three possible outcomes:

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


def login(request, user, backend=None):
    """
    Logs in the given user, persisting the user and backend in the request's session.

    Assumes that sessions are enabled, e.g. by the
    `django.contrib.sessions.middleware.SessionMiddleware` middleware.

    It is recommended to only call this function with the user returned by
    a successful call to `authenticate`.

    Two scenarios are possible:

    1. The request session does not have a user:
       The existing anonymous session data is retained. The session key is
       cycled to avoid session fixation attacks.

    2. The request session user is different from given user:
       The session is flushed to avoid reusing another user's session.
       This logs out the existing user and rotates the session key.

    Does **not** verify that the user is allowed to log in. Might result
    in inconsistent behaviour when user argument is not the return value of
    `authenticate`.

    The `backend` argument is optional. If not provided, the user's `backend`
    attribute is used. The user may not have a `backend` attribute if it was
    not retrieved using `authenticate`.

    If the user does not have a `backend` attribute, and there is only one
    authentication backend configured, that backend is used. Otherwise,
    a `ValueError` is raised.

    If no exception is raised, the CSRF token is rotated and the
    `django.contrib.auth.user_logged_in` signal is sent.

    Django listens to this signal to update the `last_login` field of the
    user object (if the field exists) with the current date and time.
    """
    # Be explicit about the expected type of the user argument. Do not handle
    # None values, unlike Django, to avoid unexpected behavior.
    # See also:
    # https://code.djangoproject.com/ticket/35530#comment:1
    if not isinstance(user, AbstractBaseUser):
        raise TypeError(f"{type(user).__name__!r} does not extend AbstractBaseUser")
    django_auth.login(request, user, backend=backend)


def logout(request):
    """
    Logs out the user, regardless of whether a user is logged in.

    Removes all session data, including the user and the CSRF token,
    and cycles the session key.

    Sends the `django.contrib.auth.user_logged_out` signal **before**
    the session is flushed. This allows listeners to access the user
    and the request before the session is reset.
    """
    # Wrap Django's logout, without altering its behavior, to add
    # a detailed docstring and provide a consistent interface for the
    # `hidp.accounts.auth` module.
    django_auth.logout(request)
