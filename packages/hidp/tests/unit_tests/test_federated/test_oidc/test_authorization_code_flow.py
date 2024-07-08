from unittest import mock

from django.test import RequestFactory, SimpleTestCase, TestCase

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
        client = NoPKCEOIDCClient(client_id="client_id")
        url = authorization_code_flow.prepare_authentication_request(
            self.request, client=client, redirect_uri="/redirect/"
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
            self.request, client=client, redirect_uri="/redirect/"
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
            self.request, client=client, redirect_uri="/redirect/"
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
        """
        It is not possible to create a PKCE challenge without first adding a state.
        """
        with self.assertRaisesMessage(
            ValueError,
            "Missing state in session. State must be added before"
            " creating a PKCE challenge.",
        ):
            authorization_code_flow.create_pkce_challenge(
                self.request, state_key="fake_state"
            )


class TestValidateAuthenticationCallback(TestCase):
    def setUp(self):
        self.session = self.client.session
        self.session[OIDC_STATES_SESSION_KEY] = {"state-123": {"test": "test"}}

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
        """ "Raises an OIDCError when the state is missing."""
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
        """ "Raises an OIDCError when the state is invalid."""
        request = RequestFactory().get("/callback/?code=code&state=state-321")
        request.session = self.session
        with self.assertRaisesMessage(
            exceptions.OIDCError, "Invalid 'state' parameter"
        ):
            authorization_code_flow.validate_authentication_callback(request)
        # The state is **not** removed, as it's not the state from the request.
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
        self.assertEqual({"test": "test"}, state)
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
        client = NoPKCEOIDCClient(client_id="client_id")
        mock_requests_post.return_value.json.return_value = self.mock_response

        tokens = authorization_code_flow.obtain_tokens(
            request=request,
            state={},
            client=client,
            code="code",
            redirect_uri="/redirect/",
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
                redirect_uri="/redirect/",
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
            redirect_uri="/redirect/",
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
            redirect_uri="/redirect/",
        )

        mock_requests_post.assert_called_once_with(
            client.token_endpoint,
            data={
                "grant_type": "authorization_code",
                "code": "code",
                "redirect_uri": "https://example.com/redirect/",
                "client_id": client.client_id,
                "client_secret": client.client_secret,
                "code_verifier": "test",
            },
            headers={
                "Accept": "application/json",
                "Origin": "https://example.com",
            },
            timeout=(5, 30),
        )
        self.assertEqual(
            self.mock_response,
            tokens,
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
        "hidp.federated.oidc.authorization_code_flow.validate_id_token",
        autospec=True,
    )
    def test_handle_callback(
        self, mock_validate_id_token, mock_obtain_tokens, mock_validate_callback
    ):
        """Handles the authentication callback and returns the tokens."""
        client = ExampleOIDCClient(client_id="client_id")

        tokens = authorization_code_flow.handle_authentication_callback(
            self.request, client=client, redirect_uri="/redirect/"
        )

        mock_validate_callback.assert_called_once_with(self.request)
        mock_obtain_tokens.assert_called_once_with(
            self.request,
            state={"code_verifier": "test"},
            client=client,
            code="code",
            redirect_uri="/redirect/",
        )
        self.assertEqual(
            {
                "access_token": "access_token",
                "id_token": "id_token",
                "token_type": "token_type",
            },
            tokens,
        )
        mock_validate_id_token.assert_called_once_with("id_token")
