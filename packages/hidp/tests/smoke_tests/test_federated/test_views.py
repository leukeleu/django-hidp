import urllib.parse

from unittest import mock

from django.test import TestCase
from django.urls import reverse

from hidp.config import configure_oidc_clients
from hidp.federated.constants import OIDC_STATES_SESSION_KEY
from hidp.federated.providers.base import OIDCClient


class ExampleOIDCClient(OIDCClient):
    # A perfectly valid OIDC client, with all the required attributes
    # and a valid provider key. It just doesn't work because it's an example.
    provider_key = "example"
    authorization_endpoint = "https://example.com/auth"
    token_endpoint = "https://example.com/token"
    userinfo_endpoint = "https://example.com/userinfo"
    jwks_uri = "https://example.com/jwks"


class TestOIDCAuthenticationRequestView(TestCase):
    def setUp(self):
        configure_oidc_clients(ExampleOIDCClient(client_id="test"))

    def test_unknown_provider(self):
        response = self.client.get(
            reverse("hidp_oidc_client:authenticate", kwargs={"provider_key": "unknown"})
        )
        self.assertEqual(response.status_code, 404)

    def test_redirects_to_provider(self):
        response = self.client.get(
            reverse("hidp_oidc_client:authenticate", kwargs={"provider_key": "example"})
        )
        state_key = next(iter(self.client.session[OIDC_STATES_SESSION_KEY]))
        callback_url = urllib.parse.quote(
            "http://testserver"
            + reverse("hidp_oidc_client:callback", kwargs={"provider_key": "example"})
        )
        self.assertRedirects(
            response,
            f"https://example.com/auth?client_id=test&response_type=code&scope=openid+email+profile&redirect_uri={callback_url}&state={state_key}",
            fetch_redirect_response=False,
        )


class TestOIDCAuthenticationCallbackView(TestCase):
    def setUp(self):
        configure_oidc_clients(ExampleOIDCClient(client_id="test"))

    def test_unknown_provider(self):
        response = self.client.get(
            reverse("hidp_oidc_client:callback", kwargs={"provider_key": "unknown"})
        )
        self.assertEqual(response.status_code, 404)

    @mock.patch(
        "hidp.federated.views.authorization_code_flow.handle_authentication_callback",
        return_value={
            "id_token": "id_token",
            "access_token": "access_token",
            "token_type": "token_type",
        },
    )
    def test_calls_handle_authentication_callback(
        self, mock_handle_authentication_callback
    ):
        response = self.client.get(
            reverse("hidp_oidc_client:callback", kwargs={"provider_key": "example"})
        )
        mock_handle_authentication_callback.assert_called_once()
        self.assertEqual(response.status_code, 200)
