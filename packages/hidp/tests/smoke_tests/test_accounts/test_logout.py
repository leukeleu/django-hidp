from http import HTTPStatus
from unittest import mock

from django.test import TestCase, override_settings
from django.urls import reverse

from hidp.accounts import auth as hidp_auth
from hidp.test.factories import user_factories


@override_settings(LOGIN_REDIRECT_URL="/", LANGUAGE_CODE="en")
class TestLogout(TestCase):
    @classmethod
    def setUpTestData(cls):
        cls.user = user_factories.UserFactory()
        cls.logout_url = reverse("hidp_accounts:logout")

    def test_get_logout(self):
        """GET is not allowed for the logout view."""
        response = self.client.get(self.logout_url)
        self.assertEqual(HTTPStatus.METHOD_NOT_ALLOWED, response.status_code)

    @mock.patch("hidp.accounts.views.hidp_auth.logout", wraps=hidp_auth.logout)
    def test_post_logout(self, mock_logout):
        self.client.post(self.logout_url)
        mock_logout.assert_called_once()

    def test_post_logout_no_login(self):
        """POST is allowed for the logout view, even if the user is not logged in."""
        session_key = self.client.session.session_key
        response = self.client.post(self.logout_url)
        self.assertRedirects(response, "/", fetch_redirect_response=False)
        self.assertNotEqual(session_key, self.client.session.session_key)

    def test_post_logout_with_login(self):
        """POST is allowed for the logout view."""
        self.client.force_login(self.user)
        session_key = self.client.session.session_key
        response = self.client.post(self.logout_url)
        self.assertRedirects(response, "/", fetch_redirect_response=False)
        self.assertNotEqual(session_key, self.client.session.session_key)

    def test_post_logout_with_safe_next_param(self):
        """Redirects to the next url, if it's safe."""
        response = self.client.post(
            self.logout_url,
            {"next": "/example/"},
        )
        self.assertRedirects(response, "/example/", fetch_redirect_response=False)

    def test_post_logout_with_unsafe_next_param(self):
        """Redirects to the default url, if the next url is unsafe."""
        response = self.client.post(
            self.logout_url,
            {"next": "https://example.com/"},
        )
        self.assertRedirects(response, "/", fetch_redirect_response=False)
