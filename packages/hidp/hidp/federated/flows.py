"""The steps of logging in with an OIDC provider, shared by the HTML and API views."""

import functools
import inspect

from enum import StrEnum

from django.conf import settings
from django.contrib.auth import BACKEND_SESSION_KEY, get_backends, get_user_model
from django.db import transaction
from django.utils import timezone
from django.utils.module_loading import import_string

from ..accounts import auth as hidp_auth
from ..config import oidc_clients
from . import tokens
from .auth.backends import OIDCModelBackend
from .models import OpenIdConnection

UserModel = get_user_model()


class RegistrationRefusedError(Exception):
    """An authentication backend refused the user who just registered."""


login_token_generator = tokens.OIDCLoginTokenGenerator()
registration_token_generator = tokens.OIDCRegistrationTokenGenerator()
link_token_generator = tokens.OIDCAccountLinkTokenGenerator()


class CallbackStep(StrEnum):
    """Where the result of logging in with a provider leads."""

    LOGIN = "login"
    REGISTER = "register"
    LINK = "link"
    ACCOUNT_EXISTS = "account_exists"


def store_token_data(request, token_generator, *, provider_key, claims, user_info):
    """Keep what the provider sent in the session, under a new token."""
    token = token_generator.make_token()
    request.session[token] = {
        "provider_key": provider_key,
        "claims": claims,
        "user_info": user_info,
    }
    return token


def get_token_data(request, token, *, token_generator):
    """
    Return the data kept under `token`, or `None`.

    `None` when the token is invalid or expired, its data is not in this session,
    or its provider is no longer registered.
    """
    if not token or not token_generator.check_token(token):
        return None
    data = request.session.get(token)
    if not data or not oidc_clients.get_oidc_client_or_none(data["provider_key"]):
        return None
    return data


def resolve_callback(request, *, provider_key, claims, user_info):
    """
    Decide the next step after logging in with a provider, and keep its data.

    Returns the step, and the token of its data (`None` for `ACCOUNT_EXISTS`).
    """
    connection = OpenIdConnection.objects.get_by_provider_and_claims(
        provider_key=provider_key,
        issuer_claim=claims["iss"],
        subject_claim=claims["sub"],
    )
    data = {"provider_key": provider_key, "claims": claims, "user_info": user_info}
    if connection:
        # A known account of the provider: log in.
        connection.last_usage = timezone.now()
        connection.save()
        return CallbackStep.LOGIN, store_token_data(
            request, login_token_generator, **data
        )
    if request.user.is_authenticated:
        # An unknown account of the provider, for a logged-in user: link it.
        return CallbackStep.LINK, store_token_data(
            request, link_token_generator, **data
        )
    if UserModel.objects.filter(email__iexact=claims["email"]).exists():
        # The email address has an account, which the user must log in to first.
        return CallbackStep.ACCOUNT_EXISTS, None
    return CallbackStep.REGISTER, store_token_data(
        request, registration_token_generator, **data
    )


@functools.cache
def _backends_accept_claims(backend_paths):
    """Return whether every OIDC backend accepts the `claims` keyword argument."""
    for backend in get_backends():
        if not isinstance(backend, OIDCModelBackend):
            continue
        parameters = inspect.signature(backend.authenticate).parameters
        if "claims" not in parameters and not any(
            parameter.kind == inspect.Parameter.VAR_KEYWORD
            for parameter in parameters.values()
        ):
            return False
    return True


def backends_accept_claims():
    # Cached per setting, so tests that override it get a fresh answer.
    return _backends_accept_claims(tuple(settings.AUTHENTICATION_BACKENDS))


def authenticate(request, token_data):
    """
    Authenticate the user of the OpenID connection in `token_data`.

    The backends get the claims of the ID token and the user info as `claims`. A
    backend without that argument would be skipped by Django, so they are left out
    when any OIDC backend does not accept them.
    """
    claims = token_data["claims"]
    credentials = {
        "provider_key": token_data["provider_key"],
        "issuer_claim": claims["iss"],
        "subject_claim": claims["sub"],
    }
    if backends_accept_claims():
        credentials["claims"] = token_data.get("user_info", {}) | claims
    return hidp_auth.authenticate(request, **credentials)


def discard_token_data(request, token):
    """Forget the data of a finished OIDC flow step."""
    request.session.pop(token, None)


def register(request, form, *, token_data):
    """
    Create the account of a first login with a provider, and return its user.

    When the provider verified the email address, the account counts as verified
    and the user is returned authenticated, ready to log in. When a backend refuses
    that user, the account is not created and `RegistrationRefusedError` is raised.
    """
    client = oidc_clients.get_oidc_client(token_data["provider_key"])
    with transaction.atomic():
        user = form.save()
        if not client.is_email_verified(
            claims=token_data["claims"], user_info=token_data["user_info"]
        ):
            return user
        user.email_verified = timezone.now()
        user.save(update_fields=["email_verified"])
        authenticated_user = authenticate(request, token_data)
        if authenticated_user is None:
            # Rolls back the account.
            raise RegistrationRefusedError
    return authenticated_user


def is_oidc_session(request):
    """
    Return whether the user of the session logged in with an OIDC provider.

    For example, for an OTP policy that leaves it to the provider.
    """
    backend_path = request.session.get(BACKEND_SESSION_KEY)
    return backend_path in settings.AUTHENTICATION_BACKENDS and issubclass(
        import_string(backend_path), OIDCModelBackend
    )
