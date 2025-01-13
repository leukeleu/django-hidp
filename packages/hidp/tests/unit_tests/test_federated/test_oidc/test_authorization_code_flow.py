import random
import time

from unittest import mock

import requests

from jwcrypto import jwt

from django.test import RequestFactory, SimpleTestCase, TestCase

from hidp import config as hidp_config
from hidp.federated.constants import OIDC_STATES_SESSION_KEY
from hidp.federated.oidc import authorization_code_flow, exceptions

from ...test_federated.test_providers.example import (
    ExampleOIDCClient,
    code_challenge_from_code_verifier,
)


class NoPKCEOIDCClient(ExampleOIDCClient):
    has_pkce_support = False


class TestAuthenticationRequestParams(SimpleTestCase):
    def test_defaults(self):
        """Passing only the required parameters results in sensible defaults."""
        params = authorization_code_flow.get_authentication_request_parameters(
            client_id="client_id",
            redirect_uri="redirect_uri",
            state="state",
        )
        self.assertEqual(
            {
                "response_type": "code",
                "client_id": "client_id",
                "scope": "openid email profile",
                "state": "state",
                "redirect_uri": "redirect_uri",
            },
            params,
        )

    def test_custom_scope(self):
        """Custom scopes are passed through."""
        params = authorization_code_flow.get_authentication_request_parameters(
            client_id="client_id",
            redirect_uri="redirect_uri",
            state="state",
            scope="openid email",
        )
        self.assertEqual(
            {
                "client_id": "client_id",
                "redirect_uri": "redirect_uri",
                "response_type": "code",
                "scope": "openid email",
                "state": "state",
            },
            params,
        )

    def test_additional_parameters(self):
        """Additional parameters are passed through."""
        params = authorization_code_flow.get_authentication_request_parameters(
            client_id="client_id",
            redirect_uri="redirect_uri",
            state="state",
            ui_locales="nl",
        )
        self.assertEqual(
            {
                "response_type": "code",
                "client_id": "client_id",
                "scope": "openid email profile",
                "redirect_uri": "redirect_uri",
                "state": "state",
                "ui_locales": "nl",
            },
            params,
        )

    def test_override_response_type(self):
        """Overriding the default response type is not allowed."""
        # The only valid value for the code flow is "code".
        params = authorization_code_flow.get_authentication_request_parameters(
            client_id="client_id",
            redirect_uri="redirect_uri",
            state="state",
            response_type="token",
        )
        self.assertEqual(
            {
                "response_type": "code",
                "client_id": "client_id",
                "scope": "openid email profile",
                "redirect_uri": "redirect_uri",
                "state": "state",
            },
            params,
        )


class TestPrepareAuthenticationRequest(TestCase):
    def setUp(self):
        self.request = RequestFactory().get("/auth/")
        self.request.session = self.client.session

    def test_no_pkce_support(self):
        """Omits PKCE parameters when the client doesn't support it."""
        client = NoPKCEOIDCClient(client_id="client_id", client_secret="client_secret")
        url = authorization_code_flow.prepare_authentication_request(
            self.request, client=client, callback_url="/redirect/"
        )
        # Adds state to session
        self.assertIn(OIDC_STATES_SESSION_KEY, self.request.session)
        state_key = next(iter(self.request.session[OIDC_STATES_SESSION_KEY].keys()))
        # Adds correct parameters to URL
        self.assertEqual(
            f"https://example.com/auth"
            f"?response_type=code"
            f"&client_id={client.client_id}"
            f"&scope=openid+email+profile"
            f"&redirect_uri=http%3A%2F%2Ftestserver%2Fredirect%2F"
            f"&state={state_key}",
            url,
        )

    def test_prepare_no_callback_base_url(self):
        """Uses the client's authorization endpoint and the request's domain."""
        client = ExampleOIDCClient(client_id="client_id")
        url = authorization_code_flow.prepare_authentication_request(
            self.request, client=client, callback_url="/redirect/"
        )
        # Adds state to session
        self.assertIn(OIDC_STATES_SESSION_KEY, self.request.session)
        state_key = next(iter(self.request.session[OIDC_STATES_SESSION_KEY].keys()))
        # Adds code_verifier to session
        self.assertIn(
            "code_verifier", self.request.session[OIDC_STATES_SESSION_KEY][state_key]
        )
        code_verifier = self.request.session[OIDC_STATES_SESSION_KEY][state_key][
            "code_verifier"
        ]
        code_challenge = code_challenge_from_code_verifier(code_verifier)
        # Adds correct parameters to URL
        self.assertEqual(
            (
                f"https://example.com/auth"
                f"?response_type=code"
                f"&client_id={client.client_id}"
                f"&scope=openid+email+profile"
                f"&redirect_uri=http%3A%2F%2Ftestserver%2Fredirect%2F"
                f"&state={state_key}"
                f"&code_challenge={code_challenge}"
                f"&code_challenge_method=S256"
            ),
            url,
        )

    def test_prepare_callback_base_url(self):
        """Uses the client's authorization endpoint and callback base URL."""
        client = ExampleOIDCClient(
            client_id="client_id",
            callback_base_url="https://example.com/",
        )
        url = authorization_code_flow.prepare_authentication_request(
            self.request, client=client, callback_url="/redirect/"
        )
        # Adds state to session
        self.assertIn(OIDC_STATES_SESSION_KEY, self.request.session)
        state_key = next(iter(self.request.session[OIDC_STATES_SESSION_KEY]))
        # Adds code_verifier to session
        self.assertIn(
            "code_verifier", self.request.session[OIDC_STATES_SESSION_KEY][state_key]
        )
        code_verifier = self.request.session[OIDC_STATES_SESSION_KEY][state_key][
            "code_verifier"
        ]
        code_challenge = code_challenge_from_code_verifier(code_verifier)
        # Adds correct parameters to URL
        self.assertEqual(
            (
                f"https://example.com/auth"
                f"?response_type=code"
                f"&client_id={client.client_id}"
                f"&scope=openid+email+profile"
                f"&redirect_uri=https%3A%2F%2Fexample.com%2Fredirect%2F"
                f"&state={state_key}"
                f"&code_challenge={code_challenge}"
                f"&code_challenge_method=S256"
            ),
            url,
        )

    def test_create_pkce_challenge_no_state(self):
        """It is not possible to create a PKCE challenge before adding a state."""
        with self.assertRaisesMessage(
            ValueError,
            "Missing state in session. State must be added before"
            " creating a PKCE challenge.",
        ):
            authorization_code_flow.create_pkce_challenge(
                self.request, state_key="fake_state"
            )

    def test_limit_concurrent_authentication_requests(self):
        """The number of concurrent authentication requests (states) is limited."""
        # States *without* creation time (precaution for old/invalid states)
        states = [{} for _ in range(25)]
        # States with a creation time in the past
        states += [{"created_at": time.time() - n * 100} for n in range(25)]
        # Shuffle the states so they are in random order
        random.shuffle(states)
        # Add the states to the session
        self.request.session[OIDC_STATES_SESSION_KEY] = {
            f"state-{n}": state for n, state in enumerate(states)
        }
        authorization_code_flow.prepare_authentication_request(
            self.request,
            client=ExampleOIDCClient(client_id="client_id"),
            callback_url="/redirect/",
        )
        # Total amount of states is limited
        self.assertEqual(25, len(self.request.session[OIDC_STATES_SESSION_KEY]))
        # New state is the first one
        self.assertNotIn(
            next(iter(self.request.session[OIDC_STATES_SESSION_KEY].values())),
            states,
        )
        # Oldest states are removed (states without a creation time are considered old).
        # States are sorted by creation time, so the last 24 states are the newest.
        self.assertSequenceEqual(
            sorted(states, key=lambda state: state.get("created_at", 0), reverse=True)[
                :24
            ],
            list(self.request.session[OIDC_STATES_SESSION_KEY].values())[1:],
        )


class TestValidateAuthenticationCallback(TestCase):
    def setUp(self):
        self.session = self.client.session
        self.states = {"state-123": {"test": "test", "created_at": time.time()}}
        self.session[OIDC_STATES_SESSION_KEY] = self.states.copy()

    def test_missing_params(self):
        """Raises an OIDCError when the code and state are missing."""
        request = RequestFactory().get("/callback/")
        request.session = self.session
        with self.assertRaisesMessage(
            exceptions.OIDCError,
            "Missing 'code' in the authentication response",
        ):
            authorization_code_flow.validate_authentication_callback(request)
        # There's no way to know which state was used, so it's **not** removed.
        self.assertIn("state-123", request.session[OIDC_STATES_SESSION_KEY])

    def test_missing_code_with_state(self):
        """Raises an OIDCError when the code is missing."""
        request = RequestFactory().get("/callback/?state=state-123")
        request.session = self.session
        with self.assertRaisesMessage(
            exceptions.OIDCError,
            "Missing 'code' in the authentication response",
        ):
            authorization_code_flow.validate_authentication_callback(request)
        # The state is removed, as the authentication failed.
        self.assertNotIn("state-123", request.session[OIDC_STATES_SESSION_KEY])

    def test_missing_state_with_code(self):
        """Raises an OIDCError when the state is missing."""
        request = RequestFactory().get("/callback/?code=code&state=")
        request.session = self.session
        with self.assertRaisesMessage(
            exceptions.OIDCError,
            "Missing 'state' in the authentication response",
        ):
            authorization_code_flow.validate_authentication_callback(request)
        # There's no way to know which state was used, so it's **not** removed.
        self.assertIn("state-123", request.session[OIDC_STATES_SESSION_KEY])

    def test_invalid_state(self):
        """Raises an OIDCError when the state is invalid."""
        request = RequestFactory().get("/callback/?code=code&state=state-321")
        request.session = self.session
        with self.assertRaisesMessage(
            exceptions.OIDCError, "Invalid 'state' parameter"
        ):
            authorization_code_flow.validate_authentication_callback(request)
        # The state is **not** removed, as it's not the state from the request.
        self.assertIn("state-123", request.session[OIDC_STATES_SESSION_KEY])

    def test_expired_state(self):
        """Raises an OIDCError when the state has expired."""
        for state in [
            {},  # Missing created_at (precaution for old/invalid states)
            {"created_at": time.time() - 3600},  # Expired
        ]:
            with self.subTest(state=state):
                request = RequestFactory().get("/callback/?code=code&state=state-321")
                request.session = self.session
                request.session[OIDC_STATES_SESSION_KEY]["state-321"] = state
                with self.assertRaisesMessage(
                    exceptions.OIDCError, "Invalid 'state' parameter"
                ):
                    authorization_code_flow.validate_authentication_callback(request)
                # The state is removed, as the authentication failed.
                self.assertNotIn("state-321", request.session[OIDC_STATES_SESSION_KEY])
                # The other state is **not** removed.
                self.assertIn("state-123", request.session[OIDC_STATES_SESSION_KEY])

    def test_error_response(self):
        """Raises an OAuth2Error when the callback contains an error response."""
        request = RequestFactory().get(
            "/callback/?error=error&error_uri=https://example.com"
        )
        request.session = self.session
        with self.assertRaisesMessage(
            exceptions.OAuth2Error, "error (https://example.com)"
        ):
            authorization_code_flow.validate_authentication_callback(request)
        # There's no way to know which state was used, so it's **not** removed.
        self.assertIn("state-123", request.session[OIDC_STATES_SESSION_KEY])

    def test_error_response_with_state(self):
        """Raises an OAuth2Error when the callback contains an error response."""
        request = RequestFactory().get(
            "/callback/?error=error&error_description=description&state=state-123"
        )
        request.session = self.session
        with self.assertRaisesMessage(exceptions.OAuth2Error, "error: description"):
            authorization_code_flow.validate_authentication_callback(request)
        # The state is removed, as the authentication failed.
        self.assertNotIn("state-123", request.session[OIDC_STATES_SESSION_KEY])

    def test_valid_callback(self):
        """Validates the callback and returns the code and state."""
        request = RequestFactory().get("/callback/?code=code&state=state-123")
        request.session = self.session
        # Extracts code and state
        code, state = authorization_code_flow.validate_authentication_callback(request)
        self.assertEqual("code", code)
        self.assertEqual(self.states["state-123"], state)
        # Removes state from session
        self.assertNotIn(
            "state-123",
            request.session[OIDC_STATES_SESSION_KEY],
        )


@mock.patch.object(
    authorization_code_flow.requests,
    "post",
    autospec=True,
)
class TestObtainTokens(SimpleTestCase):
    def setUp(self):
        self.mock_response = {
            "access_token": "access_token",
            "id_token": "id_token",
            "token_type": "token_type",
        }

    def test_obtain_tokens_no_pkce(self, mock_requests_post):
        """Omits code_verifier when PKCE is not supported."""
        request = RequestFactory().get("/callback/")
        client = NoPKCEOIDCClient(client_id="client_id", client_secret="client_secret")
        mock_requests_post.return_value.json.return_value = self.mock_response

        tokens = authorization_code_flow.obtain_tokens(
            request=request,
            state={},
            client=client,
            code="code",
            callback_url="/redirect/",
        )

        mock_requests_post.assert_called_once_with(
            client.token_endpoint,
            data={
                "grant_type": "authorization_code",
                "code": "code",
                "redirect_uri": "http://testserver/redirect/",
                "client_id": client.client_id,
            },
            headers={
                "Accept": "application/json",
                "Origin": "http://testserver",
                "Authorization": "Basic Y2xpZW50X2lkOmNsaWVudF9zZWNyZXQ=",
            },
            timeout=(5, 30),
        )
        self.assertEqual(
            self.mock_response,
            tokens,
        )

    def test_obtain_tokens_no_pkce_or_basic_auth(self, mock_requests_post):
        """Passes the client_id and client_secret as form data."""
        request = RequestFactory().get("/callback/")
        client = NoPKCEOIDCClient(client_id="client_id", client_secret="client_secret")
        client.has_basic_auth_support = False
        mock_requests_post.return_value.json.return_value = self.mock_response

        tokens = authorization_code_flow.obtain_tokens(
            request=request,
            state={},
            client=client,
            code="code",
            callback_url="/redirect/",
        )

        mock_requests_post.assert_called_once_with(
            client.token_endpoint,
            data={
                "grant_type": "authorization_code",
                "code": "code",
                "redirect_uri": "http://testserver/redirect/",
                "client_id": client.client_id,
                "client_secret": client.client_secret,
            },
            headers={
                "Accept": "application/json",
                "Origin": "http://testserver",
            },
            timeout=(5, 30),
        )
        self.assertEqual(
            self.mock_response,
            tokens,
        )

    def test_no_code_verifier_in_state(self, mock_requests_post):
        """Raises an OIDCError when the code_verifier is missing from the state."""
        request = RequestFactory().get("/callback/")
        client = ExampleOIDCClient(client_id="client_id")
        with self.assertRaisesMessage(
            exceptions.OIDCError,
            "Missing 'code_verifier' in state.",
        ):
            authorization_code_flow.obtain_tokens(
                request=request,
                state={},
                client=client,
                code="code",
                callback_url="/redirect/",
            )

    def test_obtain_tokens_no_secret(self, mock_requests_post):
        """Obtains tokens without a client secret or callback base URL."""
        request = RequestFactory().get("/callback/")
        client = ExampleOIDCClient(client_id="client_id")
        mock_requests_post.return_value.json.return_value = self.mock_response

        tokens = authorization_code_flow.obtain_tokens(
            request=request,
            state={"code_verifier": "test"},
            client=client,
            code="code",
            callback_url="/redirect/",
        )

        mock_requests_post.assert_called_once_with(
            client.token_endpoint,
            data={
                "grant_type": "authorization_code",
                "code": "code",
                "redirect_uri": "http://testserver/redirect/",
                "client_id": client.client_id,
                "code_verifier": "test",
            },
            headers={
                "Accept": "application/json",
                "Origin": "http://testserver",
            },
            timeout=(5, 30),
        )
        self.assertEqual(
            self.mock_response,
            tokens,
        )

    def test_obtain_tokens_with_secret_and_callback_base_url(self, mock_requests_post):
        """Obtains tokens with a client secret and callback base URL."""
        request = RequestFactory().get("/callback/")
        client = ExampleOIDCClient(
            client_id="client_id",
            client_secret="client_secret",
            callback_base_url="https://example.com/",
        )
        mock_requests_post.return_value.json.return_value = self.mock_response

        tokens = authorization_code_flow.obtain_tokens(
            request=request,
            state={"code_verifier": "test"},
            client=client,
            code="code",
            callback_url="/redirect/",
        )

        mock_requests_post.assert_called_once_with(
            client.token_endpoint,
            data={
                "grant_type": "authorization_code",
                "code": "code",
                "redirect_uri": "https://example.com/redirect/",
                "client_id": client.client_id,
                "code_verifier": "test",
            },
            headers={
                "Accept": "application/json",
                "Origin": "https://example.com",
                "Authorization": "Basic Y2xpZW50X2lkOmNsaWVudF9zZWNyZXQ=",
            },
            timeout=(5, 30),
        )
        self.assertEqual(
            self.mock_response,
            tokens,
        )


@mock.patch.object(
    authorization_code_flow.jwks,
    "get_oidc_client_jwks",
    autospec=True,
)
class TestParseIdToken(TestCase):
    @classmethod
    def setUpTestData(cls):
        # Generate a key and a key set
        key = jwt.JWK(generate="RSA")
        key["kid"] = key.thumbprint()
        key_set = jwt.JWKSet()
        key_set.add(key)

        # Generate an unregistered key
        unregistered_key = jwt.JWK(generate="RSA")
        unregistered_key["kid"] = unregistered_key.thumbprint()

        # Expose the keys and key set
        cls.key = key
        cls.key_set = key_set
        cls.unregistered_key = unregistered_key

    def setUp(self):
        self.client = ExampleOIDCClient(client_id="client_id")
        hidp_config.configure_oidc_clients(self.client)

    def _get_token(self, *, claims=None, key=None, key_id=None):
        key = key or self.key
        token = jwt.JWT(
            header={"alg": "RS256", "kid": key_id or key["kid"]}, claims=claims or {}
        )
        token.make_signed_token(key)
        return token.serialize()

    def test_unable_to_get_jwks(self, mock_get_oidc_client_jwks):
        """Raises an OIDCError when the signing keys cannot be retrieved."""
        mock_get_oidc_client_jwks.return_value = None
        with self.assertRaisesMessage(
            exceptions.OIDCError,
            "Unable to get signing keys for 'example'."
            " The ID Token cannot be validated.",
        ):
            authorization_code_flow.parse_id_token(
                "id_token",
                client=self.client,
            )

    def test_invalid_token(self, mock_get_oidc_client_jwks):
        """Raises an OIDCError when the token is invalid."""
        with self.assertRaisesMessage(
            exceptions.OIDCError,
            "ID Token from 'example' is invalid.",
        ):
            authorization_code_flow.parse_id_token(
                "invalid_token",
                client=self.client,
            )

    def test_unknown_key(self, mock_get_oidc_client_jwks):
        """Raises an OIDCError when the key is not in the key set."""
        mock_get_oidc_client_jwks.return_value = self.key_set
        token = self._get_token(key=self.unregistered_key)

        with self.assertRaisesMessage(
            exceptions.OIDCError,
            "ID Token from 'example' is signed with an unknown key.",
        ):
            authorization_code_flow.parse_id_token(token, client=self.client)

    def test_missing_claims(self, mock_get_oidc_client_jwks):
        """Raises an OIDCError when the claims are missing."""
        mock_get_oidc_client_jwks.return_value = self.key_set
        token = self._get_token()

        with self.assertRaisesMessage(
            exceptions.OIDCError,
            "ID Token from 'example' has invalid or missing claims:"
            " Claim sub is missing.",
        ):
            authorization_code_flow.parse_id_token(token, client=self.client)

    def test_wrong_audience(self, mock_get_oidc_client_jwks):
        """Raises an OIDCError when the audience is incorrect."""
        mock_get_oidc_client_jwks.return_value = self.key_set
        token = self._get_token(
            claims={
                "sub": "subject",
                "iss": "issuer",
                "aud": "wrong_client_id",
            },
        )

        with self.assertRaisesMessage(
            exceptions.OIDCError,
            "ID Token from 'example' has invalid or missing claims:"
            " Invalid 'aud' value.",
        ):
            authorization_code_flow.parse_id_token(token, client=self.client)

    def test_expired_token(self, mock_get_oidc_client_jwks):
        """Raises an OIDCError when the token is expired."""
        mock_get_oidc_client_jwks.return_value = self.key_set
        token = self._get_token(
            claims={
                "sub": "subject",
                "iss": "issuer",
                "aud": "client_id",
                "exp": 1234567890,
            },
        )

        with self.assertRaisesMessage(
            exceptions.OIDCError,
            "ID Token from 'example' has expired: Expired at 1234567890",
        ):
            authorization_code_flow.parse_id_token(token, client=self.client)

    def test_not_yet_valid_token(self, mock_get_oidc_client_jwks):
        """Raises an OIDCError when the token is not yet valid."""
        mock_get_oidc_client_jwks.return_value = self.key_set
        token = self._get_token(
            claims={
                "sub": "subject",
                "iss": "issuer",
                "aud": "client_id",
                "exp": time.time() + 3600,
                "iat": time.time(),
                "nbf": time.time() + 300,
            },
        )

        with self.assertRaisesMessage(
            exceptions.OIDCError,
            "ID Token from 'example' is not yet valid.",
        ):
            authorization_code_flow.parse_id_token(token, client=self.client)

    def test_wrong_issuer(self, mock_get_oidc_client_jwks):
        """Raises an OIDCError when the issuer is incorrect."""
        mock_get_oidc_client_jwks.return_value = self.key_set
        token = self._get_token(
            claims={
                "sub": "subject",
                "iss": "https://example.test",
                "aud": "client_id",
                "exp": time.time() + 3600,
                "iat": time.time(),
            },
        )

        with self.assertRaisesMessage(
            exceptions.OIDCError,
            "ID Token from 'example' is not issued by 'https://example.com',"
            " got 'https://example.test'.",
        ):
            authorization_code_flow.parse_id_token(token, client=self.client)

    def test_unexpected_nonce(self, mock_get_oidc_client_jwks):
        """Raises an OIDCError when the nonce is incorrect."""
        mock_get_oidc_client_jwks.return_value = self.key_set
        token = self._get_token(
            claims={
                "sub": "subject",
                "iss": self.client.issuer,
                "aud": self.client.client_id,
                "exp": time.time() + 3600,
                "iat": time.time(),
                "nonce": "unexpected_nonce",
            },
        )

        with self.assertRaisesMessage(
            exceptions.OIDCError,
            "ID Token from 'example' contains an unexpected 'nonce' claim.",
        ):
            authorization_code_flow.parse_id_token(token, client=self.client)

    def test_parse_id_token(self, mock_get_oidc_client_jwks):
        """Parses the ID token and returns the claims."""
        mock_get_oidc_client_jwks.return_value = self.key_set
        claims = {
            "sub": "subject",
            "iss": self.client.issuer,
            "aud": self.client.client_id,
            "exp": time.time() + 3600,
            "iat": time.time(),
        }
        token = self._get_token(claims=claims)
        parsed_claims = authorization_code_flow.parse_id_token(
            token,
            client=self.client,
        )
        self.assertEqual(claims, parsed_claims)


@mock.patch.object(
    authorization_code_flow.requests,
    "get",
    autospec=True,
)
class TestGetUserInfo(TestCase):
    @staticmethod
    def _mock_response(content, *, status_code=200):
        response = requests.Response()
        response._content = content  # noqa: SLF001 (protected attribute)
        response.status_code = status_code
        return response

    def test_request_error(self, mock_requests_get):
        """Raises an OIDCError when the request fails."""
        client = ExampleOIDCClient(client_id="client_id")
        mock_requests_get.side_effect = requests.RequestException("Request failed.")
        with self.assertRaisesMessage(
            exceptions.OIDCError,
            "Failed to fetch user information from 'example'"
            " from 'https://example.com/userinfo'.",
        ):
            authorization_code_flow.get_user_info(
                client=client,
                access_token="access_token",
                claims={"sub": "subject"},
            )

    def test_response_error(self, mock_requests_get):
        """Raises an OIDCError when the response is not OK."""
        client = ExampleOIDCClient(client_id="client_id")
        mock_requests_get.return_value = self._mock_response(
            b"Not Found", status_code=404
        )
        with self.assertRaisesMessage(
            exceptions.OIDCError,
            "Error after fetching user information from 'example'"
            " from 'https://example.com/userinfo': 404.",
        ):
            authorization_code_flow.get_user_info(
                client=client,
                access_token="access_token",
                claims={"sub": "subject"},
            )

    def test_invalid_response(self, mock_requests_get):
        """Raises an OIDCError when the response is not JSON."""
        client = ExampleOIDCClient(client_id="client_id")
        mock_requests_get.return_value = self._mock_response(
            b"Not JSON, there must be a mistake."
        )
        with self.assertRaisesMessage(
            exceptions.OIDCError,
            "Failed to parse user information from 'example'"
            " from 'https://example.com/userinfo'.",
        ):
            authorization_code_flow.get_user_info(
                client=client,
                access_token="access_token",
                claims={"sub": "subject"},
            )

    def test_wrong_sub(self, mock_requests_get):
        """Raises an OIDCError when the "sub" claim doesn't match the expected value."""
        client = ExampleOIDCClient(client_id="client_id")
        mock_requests_get.return_value.json.return_value = {
            "sub": "wrong_subject",
        }
        with self.assertRaisesMessage(
            exceptions.OIDCError,
            "User information from 'example' does not match the ID token 'sub' claim.",
        ):
            authorization_code_flow.get_user_info(
                client=client,
                access_token="access_token",
                claims={"sub": "subject"},
            )

    def test_get_user_info(self, mock_requests_get):
        """Retrieves the user info and returns the claims."""
        client = ExampleOIDCClient(client_id="client_id")
        mock_requests_get.return_value.json.return_value = {
            "sub": "subject",
        }
        user_info = authorization_code_flow.get_user_info(
            client=client,
            access_token="access_token",
            claims={"sub": "subject"},
        )
        mock_requests_get.assert_called_once_with(
            client.userinfo_endpoint,
            headers={
                "Authorization": "Bearer access_token",
                "Accept": "application/json",
            },
            timeout=(5, 30),
        )
        self.assertEqual(
            user_info,
            {
                "sub": "subject",
            },
        )


class TestHandleAuthenticationCallback(TestCase):
    def setUp(self):
        self.request = RequestFactory().get("/callback/")
        self.request.session = self.client.session

    @mock.patch(
        "hidp.federated.oidc.authorization_code_flow.validate_authentication_callback",
        autospec=True,
        return_value=("code", {"code_verifier": "test"}),
    )
    @mock.patch(
        "hidp.federated.oidc.authorization_code_flow.obtain_tokens",
        autospec=True,
        return_value={
            "access_token": "access_token",
            "id_token": "id_token",
            "token_type": "token_type",
        },
    )
    @mock.patch(
        "hidp.federated.oidc.authorization_code_flow.parse_id_token",
        autospec=True,
        return_value={"claims": "claims"},
    )
    @mock.patch(
        "hidp.federated.oidc.authorization_code_flow.get_user_info",
        autospec=True,
        return_value={"user_info": "user_info"},
    )
    def test_handle_callback(
        self,
        mock_get_user_info,
        mock_parse_id_token,
        mock_obtain_tokens,
        mock_validate_callback,
    ):
        """Handles the authentication callback and returns the tokens."""
        client = ExampleOIDCClient(client_id="client_id")

        tokens, claims, user_info, _next_url = (
            authorization_code_flow.handle_authentication_callback(
                self.request,
                client=client,
                callback_url="/redirect/",
            )
        )

        mock_validate_callback.assert_called_once_with(self.request)
        mock_obtain_tokens.assert_called_once_with(
            self.request,
            state={"code_verifier": "test"},
            client=client,
            code="code",
            callback_url="/redirect/",
        )
        mock_parse_id_token.assert_called_once_with("id_token", client=client)
        mock_get_user_info.assert_called_once_with(
            client=client,
            access_token="access_token",
            claims={"claims": "claims"},
        )

        self.assertEqual(
            {
                "access_token": "access_token",
                "id_token": "id_token",
                "token_type": "token_type",
            },
            tokens,
        )

        self.assertEqual(
            {"claims": "claims"},
            claims,
        )

        self.assertEqual(
            {"user_info": "user_info"},
            user_info,
        )
