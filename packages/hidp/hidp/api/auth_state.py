from http import HTTPStatus

from rest_framework.response import Response

from django.apps import apps

from hidp.accounts import tokens
from hidp.accounts.email_verification import get_unverified_user_from_token

from ..constants import Step
from .serializers import AuthStateSerializer

# Shared with the HTML views, so either can resume a flow the other started.
EMAIL_VERIFICATION_REQUEST_TOKEN_SESSION_KEY = "_email_verification_request_token"  # noqa: S105 (not a password)


def start_email_verification(request, user):
    """Remember in the session that `user` must verify their email address."""
    request.session[EMAIL_VERIFICATION_REQUEST_TOKEN_SESSION_KEY] = (
        tokens.email_verification_request_token_generator.make_token(user)
    )


def stop_email_verification(request):
    """Forget the pending email verification of the session."""
    request.session.pop(EMAIL_VERIFICATION_REQUEST_TOKEN_SESSION_KEY, None)


def get_email_verification_user(request):
    """Return the user whose email verification this session is waiting for."""
    return get_unverified_user_from_token(
        request.session.get(EMAIL_VERIFICATION_REQUEST_TOKEN_SESSION_KEY),
        token_generator=tokens.email_verification_request_token_generator,
    )


def _get_pending_otp_step(request):
    if not apps.is_installed("hidp.otp"):
        return None
    from hidp.otp.middleware import get_otp_middlewares  # noqa: PLC0415

    # The first policy that applies is the one that answers protected views.
    for otp_middleware in get_otp_middlewares():
        if otp_middleware.session_needs_verification(request):
            return otp_middleware.get_pending_step(request)
    return None


def get_pending_steps(request):
    """
    Return the steps the session must complete before the user is authenticated.

    A pending email verification depends on the signed token alone, so the state
    after signing up does not reveal whether the account existed.
    """
    if request.user.is_authenticated:
        step = _get_pending_otp_step(request)
        return [step] if step else []
    token = request.session.get(EMAIL_VERIFICATION_REQUEST_TOKEN_SESSION_KEY)
    if token and tokens.email_verification_request_token_generator.check_token(token):
        return [Step.EMAIL_VERIFY]
    return []


def auth_state_response(request):
    """
    Describe the authentication state of the current session.

    Responds with 200 when the user is fully authenticated, otherwise with 401 and
    the steps the client must complete next.
    """
    pending = get_pending_steps(request)
    user = request.user if request.user.is_authenticated and not pending else None
    serializer = AuthStateSerializer(
        {"user": user, "pending": [{"step": step} for step in pending]},
        context={"request": request},
    )
    return Response(
        serializer.data,
        status=HTTPStatus.OK if user is not None else HTTPStatus.UNAUTHORIZED,
    )
