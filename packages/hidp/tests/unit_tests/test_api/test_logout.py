from http import HTTPStatus

from rest_framework.test import APITestCase

from django.urls import reverse

from hidp.test.api_client import CSRFEnforcingAPIClient
from hidp.test.factories import user_factories


class TestLogoutView(APITestCase):
    @classmethod
    def setUpTestData(cls):
        cls.url = reverse("api:logout")

    def test_logout_method_get_not_allowed(self):
        response = self.client.get(self.url)
        self.assertEqual(response.status_code, HTTPStatus.METHOD_NOT_ALLOWED)

    def test_logout_without_login(self):
        """
        Verify behaviour of logout API when no user is logged in.

        - The response status code is HTTP 403 Forbidden due to missing CSRF token
        """
        # Use a CSRF enforcing client since we rely on CSRF protection in the LogoutView
        # and DRF SessionAuthentication only enforces CSRF checks for authenticated
        # users.
        client = CSRFEnforcingAPIClient()
        response = client.post(self.url)
        self.assertEqual(response.status_code, HTTPStatus.FORBIDDEN)

    def test_logout_with_login(self):
        """
        Verify behaviour of logout API when user is logged in.

        - Logged in user can access "me" endpoint
        - Logout response status code is HTTP 204 No Content
        - Logout response data is empty
        - Session is flushed after logout
        - Logged out user can no longer access "me" endpoint
        """
        user = user_factories.UserFactory()
        self.client.force_login(user=user)
        logged_in_session_key = self.client.session.session_key

        # Use the user endpoint to verify user is logged in
        me_response = self.client.get(reverse("api:user-detail", args=["me"]))
        self.assertEqual(me_response.status_code, HTTPStatus.OK)
        self.assertEqual(
            {
                "first_name": user.first_name,
                "last_name": user.last_name,
                "email": user.email,
            },
            me_response.json(),
        )

        # Logout user
        response = self.client.post(self.url)

        self.assertEqual(response.status_code, HTTPStatus.NO_CONTENT)
        self.assertIsNone(response.data)

        # Logging out should flush the session
        self.assertNotEqual(logged_in_session_key, self.client.session.session_key)

        # User is no longer able to access "me" endpoint
        me_response = self.client.get(reverse("api:user-detail", args=["me"]))
        self.assertEqual(me_response.status_code, HTTPStatus.FORBIDDEN)
        self.assertIsNone(me_response.data)
