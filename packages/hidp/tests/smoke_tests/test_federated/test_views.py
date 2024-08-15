import urllib.parse

from unittest import mock

from django.contrib import messages
from django.contrib.auth import get_user_model
from django.http import HttpRequest
from django.test import TestCase
from django.urls import reverse

from hidp.config import configure_oidc_clients
from hidp.federated.constants import OIDC_STATES_SESSION_KEY
from hidp.federated.oidc.exceptions import InvalidOIDCStateError, OAuth2Error, OIDCError
from hidp.federated.views import OIDCRegistrationView

from ...unit_tests.test_federated.test_providers.example import (
    ExampleOIDCClient,
    code_challenge_from_code_verifier,
)

UserModel = get_user_model()


class TestOIDCAuthenticationRequestView(TestCase):
    def setUp(self):
        configure_oidc_clients(ExampleOIDCClient(client_id="test"))

    def test_requires_https(self):
        response = self.client.get(
            reverse(
                "hidp_oidc_client:authenticate", kwargs={"provider_key": "example"}
            ),
            secure=False,
        )
        self.assertEqual(response.status_code, 400)

    def test_requires_post(self):
        response = self.client.get(
            reverse(
                "hidp_oidc_client:authenticate", kwargs={"provider_key": "example"}
            ),
            secure=True,
        )
        self.assertEqual(response.status_code, 405)

    def test_unknown_provider(self):
        response = self.client.post(
            reverse(
                "hidp_oidc_client:authenticate", kwargs={"provider_key": "unknown"}
            ),
            secure=True,
        )
        self.assertEqual(response.status_code, 404)

    def test_redirects_to_provider(self):
        response = self.client.post(
            reverse(
                "hidp_oidc_client:authenticate", kwargs={"provider_key": "example"}
            ),
            secure=True,
        )
        state_key = next(iter(self.client.session[OIDC_STATES_SESSION_KEY]))
        code_verifier = self.client.session[OIDC_STATES_SESSION_KEY][state_key][
            "code_verifier"
        ]
        code_challenge = code_challenge_from_code_verifier(code_verifier)
        callback_url = urllib.parse.quote(
            "https://testserver"
            + reverse("hidp_oidc_client:callback", kwargs={"provider_key": "example"})
        )
        self.assertRedirects(
            response,
            (
                f"https://example.com/auth"
                f"?client_id=test"
                f"&response_type=code"
                f"&scope=openid+email+profile"
                f"&redirect_uri={callback_url}"
                f"&state={state_key}"
                f"&code_challenge={code_challenge}"
                f"&code_challenge_method=S256"
            ),
            fetch_redirect_response=False,
        )


class TestOIDCAuthenticationCallbackView(TestCase):
    def setUp(self):
        configure_oidc_clients(ExampleOIDCClient(client_id="test"))

    def test_requires_https(self):
        response = self.client.get(
            reverse("hidp_oidc_client:callback", kwargs={"provider_key": "example"}),
            secure=False,
        )
        self.assertEqual(response.status_code, 400)

    def test_unknown_provider(self):
        response = self.client.get(
            reverse("hidp_oidc_client:callback", kwargs={"provider_key": "unknown"}),
            secure=True,
        )
        self.assertEqual(response.status_code, 404)

    @mock.patch(
        "hidp.federated.views.authorization_code_flow.handle_authentication_callback",
        return_value=(
            {
                "id_token": "id_token",
                "access_token": "access_token",
                "token_type": "token_type",
            },
            {
                "claims": "claims",
            },
            {
                "user_info": "user_info",
            },
        ),
    )
    def test_calls_handle_authentication_callback(
        self, mock_handle_authentication_callback
    ):
        response = self.client.get(
            reverse("hidp_oidc_client:callback", kwargs={"provider_key": "example"}),
            secure=True,
        )
        mock_handle_authentication_callback.assert_called_once()
        self.assertEqual(response.status_code, 200)

    @mock.patch(
        "hidp.federated.views.authorization_code_flow.handle_authentication_callback",
        side_effect=InvalidOIDCStateError("OIDC state not found"),
    )
    def test_handles_state_error(self, mock_handle_authentication_callback):
        response = self.client.get(
            reverse("hidp_oidc_client:callback", kwargs={"provider_key": "example"}),
            secure=True,
        )
        self.assertEqual(
            ["The authentication request has expired. Please try again."],
            [m.message for m in messages.get_messages(response.wsgi_request)],
        )
        self.assertRedirects(
            response,
            reverse("hidp_accounts:login"),
        )

    @mock.patch(
        "hidp.federated.views.authorization_code_flow.handle_authentication_callback",
        side_effect=OIDCError("OIDC error"),
    )
    def test_handles_oidc_error(self, mock_handle_authentication_callback):
        response = self.client.get(
            reverse("hidp_oidc_client:callback", kwargs={"provider_key": "example"}),
            secure=True,
        )
        self.assertEqual(
            ["Unexpected error during authentication. Please try again."],
            [m.message for m in messages.get_messages(response.wsgi_request)],
        )
        self.assertRedirects(
            response,
            reverse("hidp_accounts:login"),
        )

    @mock.patch(
        "hidp.federated.views.authorization_code_flow.handle_authentication_callback",
        side_effect=OAuth2Error("OAuth2 error"),
    )
    def test_handles_oauth2_error(self, mock_handle_authentication_callback):
        response = self.client.get(
            reverse("hidp_oidc_client:callback", kwargs={"provider_key": "example"}),
            secure=True,
        )
        self.assertEqual(
            ["Unexpected error during authentication. Please try again."],
            [m.message for m in messages.get_messages(response.wsgi_request)],
        )
        self.assertRedirects(
            response,
            reverse("hidp_accounts:login"),
        )


class TestOIDCRegistrationView(TestCase):
    def test_requires_token(self):
        response = self.client.get(reverse("hidp_oidc_client:register"))
        self.assertEqual(
            ["Expired or invalid token. Please try again."],
            [m.message for m in messages.get_messages(response.wsgi_request)],
        )

    def test_invalid_token(self):
        response = self.client.get(
            reverse("hidp_oidc_client:register"), {"token": "invalid"}
        )
        self.assertEqual(
            ["Expired or invalid token. Please try again."],
            [m.message for m in messages.get_messages(response.wsgi_request)],
        )

    def _add_oidc_data_to_session(self, *, save=True):
        session = self.client.session
        request = HttpRequest()
        request.session = session
        token = OIDCRegistrationView.add_data_to_session(
            request,
            provider_key="test_provider",
            claims={
                "iss": "test_issuer",
                "sub": "test_subject",
                "email": "user@example.com",
            },
            user_info={
                "given_name": "Firstname",
                "family_name": "Lastname",
            },
        )
        if save:
            session.save()
        return token

    def test_valid_token_missing_session_data(self):
        # Do not save the session to mimic an expired session or hijacked token
        token = self._add_oidc_data_to_session(save=False)
        response = self.client.get(
            reverse("hidp_oidc_client:register"), {"token": token}
        )
        self.assertEqual(
            ["Expired or invalid token. Please try again."],
            [m.message for m in messages.get_messages(response.wsgi_request)],
        )

    def test_get_with_valid_token(self):
        token = self._add_oidc_data_to_session()
        response = self.client.get(
            reverse("hidp_oidc_client:register"), {"token": token}
        )
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "federated/registration.html")

    def test_post_with_valid_token(self):
        token = self._add_oidc_data_to_session()
        self.client.post(
            reverse("hidp_oidc_client:register") + f"?token={token}",
            {"agreed_to_tos": "on"},
        )
        user = UserModel.objects.filter(email="user@example.com").first()
        self.assertIsNotNone(user, msg="Expected a user to be created.")
