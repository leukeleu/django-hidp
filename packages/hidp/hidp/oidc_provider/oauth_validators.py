from datetime import UTC
from importlib import import_module

from oauth2_provider import oauth2_validators
from oauth2_provider.models import get_access_token_model

from django.conf import settings
from django.contrib import auth
from django.contrib.auth.models import AnonymousUser
from django.http import HttpRequest, parse_cookie
from django.utils import timezone
from django.utils.timezone import localtime

AccessTokenModel = get_access_token_model()


def _get_user_from_oauthlib_request(request):
    # Request is an oauthlib request, not a Django request, so the session
    # and user need to be determined from the headers.
    cookies = parse_cookie(request.headers["HTTP_COOKIE"])
    session_id = cookies.get(settings.SESSION_COOKIE_NAME)
    if not session_id:
        # Session cookie not found, no user to authenticate.
        return AnonymousUser()
    # auth.get_user requires a Django request, with a session object,
    # in order to look up the user. Create a dummy request object and
    # load the session identified by the session cookie.
    session_engine = import_module(settings.SESSION_ENGINE)
    request = HttpRequest()
    request.session = session_engine.SessionStore(session_id)
    # Find the user associated with the session and return it.
    # If no user is logged in AnonymousUser will be returned.
    return auth.get_user(request)


class OAuth2Validator(oauth2_validators.OAuth2Validator):
    def validate_silent_login(self, request):  # noqa: PLR6301 (no-self-use)
        """
        Check if the user is logged in to determine if silent login is possible.

        This is further validated in `validate_silent_authorization`.
        """
        # Assign the user to the oauthlib request object.
        request.user = _get_user_from_oauthlib_request(request)
        # Silently authenticate the user if the user is logged in.
        return request.user.is_authenticated

    def validate_silent_authorization(self, request):  # noqa: PLR6301 (no-self-use)
        """
        Determine if the logged-in user has authorized the application.

        If so, silent authorization is possible.
        """
        # validate_silent_login is called before validate_silent_authorization,
        # so the user *should* be assigned to the request object.
        user = getattr(request, "user", None)
        if not user or not user.is_authenticated:
            return False

        if request.client.skip_authorization:
            # The client has been configured to skip the authorization step.
            return True

        # DOT does not record whether a user has consented to an application.
        # It assumes that, if an active access token exists, the user has consented.
        # Once the access tokens expire, the user will need to re-consent.
        tokens = AccessTokenModel.objects.filter(
            user=request.user, application=request.client, expires__gte=timezone.now()
        ).all()
        return any(token.allow_scopes(request.scopes) for token in tokens)

    # Maps OIDC claims to scopes. This is used to determine which claims to include
    # in the ID token and user info response.
    oidc_claim_scope = oauth2_validators.OAuth2Validator.oidc_claim_scope

    def get_additional_claims(self, request):
        """
        Map user attributes to OIDC claims.

        These claims are included in the ID token and user info response.

        Only those claims that belong to the requested scopes are included.
        This means that, for example, if the client only requests the `openid` scope,
        none of the additional claims will be included in the ID token.

        The mapping of claims to scopes is defined in the `oidc_claim_scope` dictionary.
        """
        return super().get_additional_claims(request) | {
            "name": request.user.get_full_name(),
            "given_name": request.user.first_name,
            "family_name": request.user.last_name,
            "updated_at": int(localtime(request.user.last_modified, UTC).timestamp()),
            "email": request.user.email,
            "email_verified": request.user.email_verified is not None,
        }
