"""Functions to handle the OIDC Authorization Code Flow, with optional PKCE support."""

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
import collections
import hashlib
import json
import secrets
import time

from datetime import timedelta
from urllib.parse import urlencode, urljoin, urlsplit

import requests

from jwcrypto import jwt

from ..constants import OIDC_STATES_SESSION_KEY
from . import jwks
from .exceptions import InvalidOIDCStateError, OAuth2Error, OIDCError

# Maximum number of concurrent state entries (authentication requests)
# that can be stored in the session. It should be enough to handle
# concurrent requests, but within reason.
_OIDC_MAX_STATE_ENTRIES = 25

# How long the state should be stored in the session.
#
# This is the maximum amount of time between the initial authentication
# request and the callback from the OpenID Connect provider.
#
# This should be a middle ground between security and usability.
#
# State should be kept for long enough to allow for the following scenarios:
# - Network latency (the user might be on a slow connection).
# - The user might be going through a password reset flow at the provider.
#
# However, state should not be kept for too long, as:
# - The user might simply get distracted.
# - The user might close the browser and come back later.
# - The user might just abandon the authentication process.
#
# So, at some point, the state should be considered stale and removed.
_OIDC_STATE_TTL = timedelta(minutes=15).total_seconds()


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


def _clamp_state_entries(states):
    """
    Clamps the number of state entries to the maximum allowed.

    If the number of state entries exceeds the maximum, the oldest
    entries are removed.
    """
    return dict(
        sorted(
            states.items(), key=lambda item: item[1].get("created_at", 0), reverse=True
        )[:_OIDC_MAX_STATE_ENTRIES]
    )


def _add_state_to_session(request, state_key, *, next_url=None):
    """Adds a state to the session, to be used in the authentication response."""
    # Multiple concurrent authentication requests might be happening at the
    # same time. A dictionary is used to store the state for each request.
    states = request.session.get(OIDC_STATES_SESSION_KEY, {})
    states[state_key] = {
        # Allow the state to expire after a certain amount of time.
        "created_at": time.time(),
        "next_url": next_url,
    }
    request.session[OIDC_STATES_SESSION_KEY] = _clamp_state_entries(states)


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
    Prepares the parameters for an authentication request.

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
    Prepares the PKCE challenge for an authentication request.

    Associates the code verifier with the state so it can be sent to
    the token endpoint for verification during the token exchange.
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


def prepare_authentication_request(
    request,
    *,
    client,
    callback_url,
    next_url=None,
    **extra_params,
):
    """
    Prepares an authentication request for an OpenID Connect Authorization Code Flow.

    Arguments:
        request (HttpRequest):
            The current HTTP request.
        client (OIDCClient):
            The OpenID Connect client to use for the authentication request.
        callback_url (str):
            The (relative) URL to redirect the user to after the authentication.
        next_url (str | None):
            The URL to redirect the user to after completing the entire OIDC flow.
        extra_params (dict):
            Additional parameters to include in the authentication request.

    Returns:
        str: The URL to redirect the user to for the authentication.
    """
    # 2.1.1. Client Prepares Authentication Request
    # https://openid.net/specs/openid-connect-basic-1_0.html#AuthenticationRequest
    state_key = secrets.token_urlsafe(32)
    _add_state_to_session(request, state_key, next_url=next_url)

    request_parameters = get_authentication_request_parameters(
        client_id=client.client_id,
        redirect_uri=_build_absolute_uri(request, client, callback_url),
        state=state_key,
        scope=client.scope,
        **extra_params,
    )

    if client.has_pkce_support:
        # Add PKCE parameters to the request.
        request_parameters |= create_pkce_challenge(request, state_key=state_key)

    return urljoin(
        client.authorization_endpoint,
        f"?{urlencode(request_parameters)}",
    )


def _cull_expired_states(states):
    """
    Removes stale state entries from the session.

    The state is considered stale if it has been stored for longer
    than the configured TTL.
    """
    now = time.time()
    return {
        state_key: state
        for state_key, state in states.items()
        if now - state.get("created_at", 0) <= _OIDC_STATE_TTL
    }


def _pop_state_from_session(request, state_key):
    """
    Returns the state stored in the session for the given state ID.

    The state is removed from the session once it has been retrieved.
    If the state is not found, returns None.
    """
    # Get the known states from the session, culling any stale states.
    states = _cull_expired_states(request.session.get(OIDC_STATES_SESSION_KEY, {}))
    # Remove the requested state from the known states.
    state = states.pop(state_key, None)
    # Update the session with the modified states. This is necessary to
    # ensure that the state is not used more than once.
    request.session[OIDC_STATES_SESSION_KEY] = states
    return state


def validate_authentication_callback(request):
    """
    Validates the callback from an OIDC authentication request.

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
        # State is not present in the session (invalid or expired).
        raise InvalidOIDCStateError(
            "Invalid 'state' parameter in the authentication response."
        )

    return code, state


def obtain_tokens(request, *, state, client, code, callback_url):
    """
    Obtains the tokens from an OIDC authentication request.

    Arguments:
        request (HttpRequest):
            The current HTTP request.
        state (dict):
            The state associated with the authentication request.
        client (OIDCClient):
            The OpenID Connect client to use for the authentication request.
        code (str):
            The code received in the callback from the authentication request.
        callback_url (str):
            The (relative) URL to redirect the user to after authentication.

    Returns:
        dict: The token response from the OpenID Connect provider.
    """
    # 2.1.6. Client Obtains ID Token and Access Token
    # https://openid.net/specs/openid-connect-basic-1_0.html#ObtainingTokens

    # 2.1.6.1. Client Sends Code
    # https://openid.net/specs/openid-connect-basic-1_0.html#TokenRequest

    redirect_uri = _build_absolute_uri(request, client, callback_url)
    redirect_uri_origin = "://".join(urlsplit(redirect_uri)[:2])

    token_request_data = {
        "grant_type": "authorization_code",
        "code": code,
        "redirect_uri": redirect_uri,
        "client_id": client.client_id,
    }
    token_request_headers = {
        "Accept": "application/json",
        # Some providers (e.g. Microsoft) require the Origin header
        # to be present and equal the redirect URI origin.
        "Origin": redirect_uri_origin,
    }

    if client.client_secret:
        # Some providers require the client secret to be included in the token request.
        if client.has_basic_auth_support:
            # The Client MUST authenticate to the Token Endpoint using the
            # HTTP Basic method [...].
            basic_auth_credentials = base64.b64encode(
                f"{client.client_id}:{client.client_secret}".encode()
            ).decode()
            token_request_headers |= {
                "Authorization": f"Basic {basic_auth_credentials}"
            }
        else:
            # Some providers (e.g. LinkedIn) require the client secret to be included
            # in the request body instead.
            token_request_data |= {"client_secret": client.client_secret}

    if client.has_pkce_support:
        if "code_verifier" not in state:
            raise OIDCError("Missing 'code_verifier' in state.")
        # 4.5. Client Sends [...] the Code Verifier to the Token Endpoint
        # https://www.rfc-editor.org/rfc/rfc7636.html#section-4.5
        token_request_data["code_verifier"] = state["code_verifier"]

    # 2.1.6.2. Client Receives Tokens
    # https://openid.net/specs/openid-connect-basic-1_0.html#TokenOK
    return requests.post(
        client.token_endpoint,
        data=token_request_data,
        headers=token_request_headers,
        # Timeouts in seconds
        timeout=(
            5,  # Connect timeout
            30,  # Read timeout
        ),
    ).json()


def parse_id_token(raw_id_token, *, client):
    """
    Asserts that the given ID Token is valid and issued by the expected OIDC provider.

    Arguments:
        raw_id_token (str):
            The ID Token to validate.
        client (OIDCClient):
            The OpenID Connect client used to obtain the token.

    Returns:
        dict: The claims from the ID Token.

    Raises:
        OIDCError: If the ID Token is invalid. The authentication process
                   should be aborted and the token should not be used.
    """
    # 2.2. ID Token
    # The ID Token is a security token that contains Claims about the
    # authentication of an End-User by an Authorization Server when using a
    # Client, and potentially other requested Claims. The ID Token is
    # represented as a JSON Web Token (JWT).
    #
    # https://openid.net/specs/openid-connect-basic-1_0.html#IDToken

    # 2.2.1. ID Token Validation
    # The Client MUST validate the ID Token in the Token Response.
    #
    # If any of the validation procedures [...] fail, any operations requiring
    # the information that failed to correctly validate MUST be aborted
    # and the information that failed to validate MUST NOT be used.
    #
    # https://openid.net/specs/openid-connect-basic-1_0.html#IDTokenValidation

    # Parse the token and validate in a way that goes beyond the basic
    # validation described in the OpenID Connect Basic Implementer's Guide.
    # Besides checking the claims, this also validates that the token is
    # signed with the expected algorithm and that the signature is valid.

    # To check the signature, the public key(s) of the OpenID Connect provider
    # must be obtained.
    keys = jwks.get_oidc_client_jwks(client)
    if keys is None:
        raise OIDCError(
            f"Unable to get signing keys for {client.provider_key!r}."
            " The ID Token cannot be validated."
        )

    try:
        # Parse the token, check the signature and perform basic claim validation.
        id_token = jwt.JWT(
            jwt=raw_id_token,
            # Only accept tokens signed with RSA using SHA-256 hash algorithm.
            algs=["RS256"],
            # A signed token is expected (as opposed to an encrypted token).
            expected_type="JWS",
            # Use the public keys of the provider to verify the signature.
            key=keys,
            # Make sure claims are available for further validation.
            check_claims={
                "sub": None,  # Present
                "iss": None,  # Present (value is checked later)
                "aud": client.client_id,  # Must match the client ID
                "exp": None,  # Not expired (current time + 1 minute leeway)
                "iat": None,  # Present
            },
        )
        claims = json.loads(id_token.claims)
    except jwt.JWTMissingKey:
        # The token is signed with an unknown key.
        raise OIDCError(
            f"ID Token from {client.provider_key!r} is signed with an unknown key."
        ) from None
    except (jwt.JWTInvalidClaimValue, jwt.JWTMissingClaim) as exc:
        # Claim verification failed.
        raise OIDCError(
            f"ID Token from {client.provider_key!r} has invalid or missing"
            f" claims: {exc}."
        ) from None
    except jwt.JWTExpired as exc:
        # Token is expired.
        raise OIDCError(
            f"ID Token from {client.provider_key!r} has expired: {exc}."
        ) from None
    except (ValueError, jwt.JWException) as exc:
        # Token is invalid.
        raise OIDCError(f"ID Token from {client.provider_key!r} is invalid.") from exc
    else:
        # Check if the token is currently valid.
        if "nbf" in claims and claims["nbf"] > time.time():
            # The token is not valid yet.
            raise OIDCError(f"ID Token from {client.provider_key!r} is not yet valid.")

        # The token is valid, and not expired.
        # The required claims are available for further validation.

        # Check the issuer
        if claims["iss"] != (expected_issuer := client.get_issuer(claims=claims)):
            # The issuer is not the expected one.
            raise OIDCError(
                f"ID Token from {client.provider_key!r} is not issued by"
                f" {expected_issuer!r}, got {claims['iss']!r}."
            )

        # Make sure the nonce claim is absent or empty. It is not sent in the
        # authentication request, so it should not be present in the ID Token.
        if claims.get("nonce"):
            raise OIDCError(
                f"ID Token from {client.provider_key!r} contains an unexpected"
                f" 'nonce' claim."
            )

        # Everything checks out.
        return claims


def get_user_info(*, client, access_token, claims):
    """
    Obtains the user information from an OpenID Connect provider.

    Arguments:
        client (OIDCClient):
            The OpenID Connect client used to obtain the token.
        access_token (str):
            The access token to use to retrieve the user information.
        claims (dict):
            The claims from the ID Token

    Returns:
        dict: The user information from the OpenID Connect provider.
    """
    # 2.3.1. UserInfo Request
    # Clients send requests to the UserInfo Endpoint to obtain Claims about
    # the End-User using an Access Token obtained through [...] Authentication.
    # https://openid.net/specs/openid-connect-basic-1_0.html#UserInfoRequest

    try:
        # The request SHOULD use the HTTP GET method [...]
        response = requests.get(
            client.userinfo_endpoint,
            headers={
                # the Access Token SHOULD be sent using the Authorization header field.
                "Authorization": f"Bearer {access_token}",
                "Accept": "application/json",
            },
            # Generous timeouts
            timeout=(
                5,  # Connect timeout
                30,  # Read timeout
            ),
        )
    except requests.RequestException as exc:
        raise OIDCError(
            f"Failed to fetch user information from {client.provider_key!r}"
            f" from {client.userinfo_endpoint!r}."
        ) from exc

    try:
        response.raise_for_status()
    except requests.RequestException as exc:
        raise OIDCError(
            f"Error after fetching user information from {client.provider_key!r}"
            f" from {client.userinfo_endpoint!r}: {response.status_code}."
        ) from exc

    # 2.3.2. Successful UserInfo Response
    # https://openid.net/specs/openid-connect-basic-1_0.html#UserInfoResponse
    try:
        # The UserInfo Claims MUST be returned as the members of a JSON object.
        user_info = client.normalize_userinfo(userinfo=response.json())
    except json.JSONDecodeError as exc:
        raise OIDCError(
            f"Failed to parse user information from {client.provider_key!r}"
            f" from {client.userinfo_endpoint!r}."
        ) from exc

    # The sub Claim in the UserInfo Response MUST be verified to exactly match
    # the sub Claim in the ID Token; if they do not match, the UserInfo Response
    # values MUST NOT be used.
    if "sub" not in user_info or user_info["sub"] != claims["sub"]:
        raise OIDCError(
            f"User information from {client.provider_key!r} does not match the"
            f" ID token 'sub' claim."
        )

    return user_info


_AuthenticationResult = collections.namedtuple(
    "_AuthenticationResult", ["tokens", "claims", "user_info", "next_url"]
)


def handle_authentication_callback(request, *, client, callback_url):
    """
    Handles the callback from an OIDC authentication request.

    Arguments:
        request (HttpRequest):
            The current HTTP request.
        client (OIDCClient):
            The OpenID Connect client to use for the authentication request.
        callback_url (str):
            The (relative) URL to redirect the user to after authentication.

    Returns:
        _AuthenticationResult:
            A named tuple with the tokens, claims, and user
            information obtained from the authentication

    Raises:
        OAuth2Error: If the callback contains an error.
        OIDCError: If the callback is invalid.
    """
    code, state = validate_authentication_callback(request)
    token_response = obtain_tokens(
        request,
        state=state,
        client=client,
        code=code,
        callback_url=callback_url,
    )
    if "error" in token_response:
        raise OAuth2Error(
            token_response["error"],
            description=token_response.get("error_description"),
            uri=token_response.get("error_uri"),
        )
    claims = parse_id_token(token_response.get("id_token"), client=client)
    user_info = get_user_info(
        client=client, access_token=token_response["access_token"], claims=claims
    )
    return _AuthenticationResult(
        tokens=token_response,
        claims=claims,
        user_info=user_info,
        next_url=state.get("next_url"),
    )
