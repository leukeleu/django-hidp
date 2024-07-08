"""
Functions to handle the OpenID Connect Authorization Code Flow,
with support for the optional PKCE extension.
"""

# 2.1.  Code Flow
#
# The Code Flow consists of the following steps:
#
# 1. Client prepares an Authentication Request containing the desired
#    request parameters.
# 2. Client sends the request to the Authorization Server.
# 3. Authorization Server authenticates the End-User.
# 4. Authorization Server obtains End-User Consent/Authorization.
# 5. Authorization Server sends the End-User back to the Client with code.
# 6. Client sends the code to the Token Endpoint to receive an Access Token
#    and ID Token in the response.
# 7. Client validates the tokens and retrieves the End-User's Subject Identifier.
#
# https://openid.net/specs/openid-connect-basic-1_0.html#CodeFlow

import base64
import hashlib
import secrets
import string

from urllib.parse import urlencode, urljoin

import requests

from ..constants import OIDC_STATES_SESSION_KEY
from .exceptions import OAuth2Error, OIDCError

# URL-safe characters
_SAFE_CHARACTERS = string.ascii_letters + string.digits + "_.-"


def _build_absolute_uri(request, client, redirect_uri):
    """
    Builds an absolute URI for the redirect URI.

    Uses the current request base URL, unless the client defines a
    callback base URL.
    """
    return urljoin(
        client.callback_base_url or request.build_absolute_uri("/"),
        redirect_uri,
    )


def _get_random_string(length):
    return "".join(secrets.choice(_SAFE_CHARACTERS) for _ in range(length))


def _add_state_to_session(request, state_key):
    """
    Adds a state to the session, to be used in the authentication response.
    """
    # Multiple concurrent authentication requests might be happening at the
    # same time. A dictionary is used to store the state for each request.
    states = request.session.get(OIDC_STATES_SESSION_KEY, {})
    states[state_key] = {}
    request.session[OIDC_STATES_SESSION_KEY] = states


def _add_code_verifier_to_session(request, state_key, code_verifier):
    """
    Associate the code verifier with the state.

    This is necessary in order to send it to the token endpoint for verification.
    """
    if (
        OIDC_STATES_SESSION_KEY not in request.session
        or state_key not in request.session[OIDC_STATES_SESSION_KEY]
    ):
        raise ValueError(
            "Missing state in session. State must be added before creating"
            " a PKCE challenge."
        )

    request.session[OIDC_STATES_SESSION_KEY][state_key]["code_verifier"] = code_verifier
    # Django doesn't detect changes to mutable objects stored in the session.
    # Manually mark the session as modified to ensure the changes are saved.
    request.session.modified = True


def get_authentication_request_parameters(
    *, client_id, redirect_uri, state, scope="openid email profile", **extra_params
):
    """
    Returns a dictionary with parameters for an OpenID Connect
    Authorization Code Flow authentication request.

    Arguments:
        client_id (str):
            The client ID provided by the OpenID Connect provider.
        redirect_uri (str):
            The absolute URL to redirect the user to after the authentication.
        state (str):
            A unique value to prevent CSRF attacks.
        scope (str):
            The requested scope for the authentication.
        **extra_params:
            Additional parameters to include in the authentication request.

    Returns:
        dict: The parameters for the authentication request.
    """
    # 2.1.1.1. Request Parameters
    # https://openid.net/specs/openid-connect-basic-1_0.html#RequestParameters
    return extra_params | {
        "response_type": "code",
        "client_id": client_id,
        "scope": scope,
        "redirect_uri": redirect_uri,
        "state": state,
    }


def create_pkce_challenge(request, *, state_key):
    """
    Returns a dictionary with parameters for the Proof Key for Code Exchange
    (PKCE) extension to an OpenID Connect Authorization Code Flow.

    Associates the code verifier with the state, to be used in the token
    exchange request.
    """
    # 4.1. Client Creates a Code Verifier
    # code_verifier [is a] [...] random STRING with a minimum length
    # of 43 characters and a maximum length of 128 characters.
    # https://www.rfc-editor.org/rfc/rfc7636.html#section-4.1

    # 64 bytes, encoded in base64, is 86 characters long.
    # This is within the recommended range of 43 to 128 characters.
    code_verifier = secrets.token_urlsafe(64)
    _add_code_verifier_to_session(request, state_key, code_verifier)

    # 4.2. Client Creates the Code Challenge
    # "S256" is Mandatory To Implement (MTI) on the server. Clients are
    # permitted to use "plain" only if they cannot support "S256" for some
    # technical reason [...].
    # https://www.rfc-editor.org/rfc/rfc7636.html#section-4.2

    # The code challenge is the SHA-256 hash of the code verifier, encoded
    # as a URL-safe base64 string without padding.
    code_challenge = (
        base64.urlsafe_b64encode(
            hashlib.sha256(code_verifier.encode("ascii")).digest()
        ).decode("ascii")
    ).rstrip("=")  # Strip padding

    # 4.3. Client Sends the Code Challenge with the Authorization Request
    # https://www.rfc-editor.org/rfc/rfc7636.html#section-4.3
    return {
        "code_challenge": code_challenge,
        "code_challenge_method": "S256",
    }


def prepare_authentication_request(request, *, client, redirect_uri, **extra_params):
    """
    Prepares an authentication request for an OpenID Connect Authorization Code Flow.

    Arguments:
        request (HttpRequest):
            The current HTTP request.
        client (OIDCClient):
            The OpenID Connect client to use for the authentication request.
        redirect_uri (str):
            The (relative) URL to redirect the user to after the authentication.
        extra_params (dict):
            Additional parameters to include in the authentication request.

    Returns:
        str: The URL to redirect the user to for the authentication.
    """
    # 2.1.1. Client Prepares Authentication Request
    # https://openid.net/specs/openid-connect-basic-1_0.html#AuthenticationRequest
    state_key = _get_random_string(32)
    _add_state_to_session(request, state_key)

    redirect_uri = _build_absolute_uri(request, client, redirect_uri)
    request_parameters = get_authentication_request_parameters(
        client_id=client.client_id,
        redirect_uri=redirect_uri,
        state=state_key,
        **extra_params,
    )

    if client.has_pkce_support:
        # Add PKCE parameters to the request.
        request_parameters |= create_pkce_challenge(request, state_key=state_key)

    return urljoin(
        client.authorization_endpoint,
        f"?{urlencode(request_parameters)}",
    )


def _pop_state_from_session(request, state_key):
    """
    Returns the state stored in the session for the given state ID.
    The state is removed from the session once it has been retrieved.
    If the state is not found, returns None.
    """
    states = request.session.get(OIDC_STATES_SESSION_KEY, {})
    # Remove the requested state from the known states.
    state = states.pop(state_key, None)
    # Update the session with the modified states. This is necessary to
    # ensure that the state is not used more than once.
    request.session[OIDC_STATES_SESSION_KEY] = states
    return state


def validate_authentication_callback(request):
    """
    Validates the callback from an OpenID Connect Authorization Code Flow
    authentication request.

    Arguments:
        request (HttpRequest):
            The current HTTP request.

    Returns:
        tuple (str, dict):
            A tuple containing the code and state associated with the callback.

    Raises:
        OAuth2Error: If the callback contains an error.
        OIDCError: If the callback is invalid.
    """
    # 2.1.5. Authorization Server Sends End-User Back to Client
    # Once the authorization is determined, the Authorization Server
    # returns a successful response or an error response.
    # https://openid.net/specs/openid-connect-basic-1_0.html#CodeResponse

    # 2.1.5.1. End-User Grants Authorization
    # If the End-User grants the access request, the Authorization Server
    # Issues a code and delivers it to the Client [...].
    # https://openid.net/specs/openid-connect-basic-1_0.html#CodeOK
    code = request.GET.get("code")
    state_key = request.GET.get("state")

    # 2.1.5.2. End-User Denies Authorization or Invalid Request
    # If the End-User denies the authorization or the End-User
    # authentication fails, the Authorization Server MUST return the error
    # Authorization Response as defined in Section 4.1.2.1 of OAuth 2.0
    # https://www.rfc-editor.org/rfc/rfc6749.html#section-4.1.2.1
    # https://openid.net/specs/openid-connect-basic-1_0.html#CodeAuthzError
    error = request.GET.get("error")
    if error:
        # Remove the state from the session, authentication failed
        # and the state should not be used again.
        _pop_state_from_session(request, state_key)
        raise OAuth2Error(
            error,
            description=request.GET.get("error_description"),
            uri=request.GET.get("error_uri"),
        )

    for param, value in (("code", code), ("state", state_key)):
        if not value:
            # Remove the state from the session, authentication failed
            # and the state should not be used again.
            _pop_state_from_session(request, state_key)
            raise OIDCError(f"Missing {param!r} in the authentication response.")

    state = _pop_state_from_session(request, state_key)
    if state is None:
        raise OIDCError("Invalid 'state' parameter in the authentication response.")

    return code, state


def obtain_tokens(request, *, client, code, redirect_uri):
    """
    Obtains the tokens from an OpenID Connect Authorization Code Flow
    authentication request.

    Arguments:
        request (HttpRequest):
            The current HTTP request.
        client (OIDCClient):
            The OpenID Connect client to use for the authentication request.
        code (str):
            The code received in the callback from the authentication request.
        redirect_uri (str):
            The (relative) URL to redirect the user to after the authentication.

    Returns:
        dict: The token response from the OpenID Connect provider.
    """
    # 2.1.6. Client Obtains ID Token and Access Token
    # https://openid.net/specs/openid-connect-basic-1_0.html#ObtainingTokens

    # 2.1.6.1. Client Sends Code
    # https://openid.net/specs/openid-connect-basic-1_0.html#TokenRequest

    token_request_data = {
        "grant_type": "authorization_code",
        "code": code,
        "redirect_uri": _build_absolute_uri(request, client, redirect_uri),
        "client_id": client.client_id,
    }
    if client.client_secret:
        # Some providers require the client secret to be included
        # in the token request.
        token_request_data["client_secret"] = client.client_secret

    # 2.1.6.2. Client Receives Tokens
    # https://openid.net/specs/openid-connect-basic-1_0.html#TokenOK
    return requests.post(
        client.token_endpoint,
        data=token_request_data,
        headers={
            "Accept": "application/json",
        },
        # Generous timeouts, might reconsider
        timeout=(
            5,  # Connect timeout
            30,  # Read timeout
        ),
    ).json()


def validate_id_token(id_token):
    # 2.2.1. ID Token Validation
    # The Client MUST validate the ID Token in the Token Response.
    # https://openid.net/specs/openid-connect-basic-1_0.html#IDTokenValidation
    ...  # TODO: Implement ID Token validation


def handle_authentication_callback(request, *, client, redirect_uri):
    """
    Handles the callback from an OpenID Connect Authorization Code Flow
    authentication request.

    Arguments:
        request (HttpRequest):
            The current HTTP request.
        client (OIDCClient):
            The OpenID Connect client to use for the authentication request.
        redirect_uri (str):
            The (relative) URL to redirect the user to after the authentication.

    Returns:
        dict: The token response from the OpenID Connect provider.

    Raises:
        OAuth2Error: If the callback contains an error.
        OIDCError: If the callback is invalid.
    """
    code, state = validate_authentication_callback(request)  # noqa: F841 (state is not used **yet**)
    token_response = obtain_tokens(
        request, client=client, code=code, redirect_uri=redirect_uri
    )
    validate_id_token(token_response.get("id_token"))
    return token_response
