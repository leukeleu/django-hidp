import urllib.parse

from http import HTTPStatus
from unittest import mock

from django.contrib.auth import get_user_model
from django.core import mail
from django.http import HttpRequest
from django.test import TestCase
from django.urls import reverse

from hidp.config import configure_oidc_clients
from hidp.federated import models, views
from hidp.federated.constants import OIDC_STATES_SESSION_KEY
from hidp.federated.oidc.exceptions import InvalidOIDCStateError, OAuth2Error, OIDCError
from hidp.test.factories import user_factories

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

    def test_stores_next_url_with_state(self):
        self.client.post(
            reverse(
                "hidp_oidc_client:authenticate", kwargs={"provider_key": "example"}
            ),
            {"next": "/next"},
            secure=True,
        )
        state_key = next(iter(self.client.session[OIDC_STATES_SESSION_KEY]))
        self.assertEqual(
            self.client.session[OIDC_STATES_SESSION_KEY][state_key]["next_url"], "/next"
        )


_VALID_AUTH_CALLBACK = (
    {
        "id_token": "id_token",
        "access_token": "access_token",
        "token_type": "token_type",
    },
    {
        "iss": "example",
        "sub": "test_subject",
        "email": "user@example.com",
    },
    {
        "given_name": "Firstname",
        "family_name": "Lastname",
    },
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
        return_value=(*_VALID_AUTH_CALLBACK, None),
    )
    def test_calls_handle_authentication_callback(
        self, mock_handle_authentication_callback
    ):
        response = self.client.get(
            reverse("hidp_oidc_client:callback", kwargs={"provider_key": "example"}),
            secure=True,
            follow=False,
        )
        mock_handle_authentication_callback.assert_called_once()
        # Redirects to the next url
        self.assertEqual(response.status_code, HTTPStatus.FOUND)

    @mock.patch(
        "hidp.federated.views.authorization_code_flow.handle_authentication_callback",
        return_value=(*_VALID_AUTH_CALLBACK, "/next"),
    )
    def test_restores_next_url(self, mock_handle_authentication_callback):
        response = self.client.get(
            reverse("hidp_oidc_client:callback", kwargs={"provider_key": "example"}),
            secure=True,
            follow=False,
        )
        query = urllib.parse.parse_qs(urllib.parse.urlparse(response.url).query)
        self.assertIn("next", query)
        self.assertEqual(query["next"][0], "/next")

    @mock.patch(
        "hidp.federated.views.authorization_code_flow.handle_authentication_callback",
        side_effect=InvalidOIDCStateError("OIDC state not found"),
    )
    def test_handles_state_error(self, mock_handle_authentication_callback):
        response = self.client.get(
            reverse("hidp_oidc_client:callback", kwargs={"provider_key": "example"}),
            secure=True,
            follow=True,
        )
        self.assertTemplateUsed(response, "hidp/accounts/login.html")
        self.assertInHTML(
            "The authentication request has expired. Please try again.",
            response.content.decode("utf-8"),
        )

    @mock.patch(
        "hidp.federated.views.authorization_code_flow.handle_authentication_callback",
        side_effect=OIDCError("OIDC error"),
    )
    def test_handles_oidc_error(self, mock_handle_authentication_callback):
        response = self.client.get(
            reverse("hidp_oidc_client:callback", kwargs={"provider_key": "example"}),
            secure=True,
            follow=True,
        )
        self.assertTemplateUsed(response, "hidp/accounts/login.html")
        self.assertInHTML(
            "An unexpected error occurred during authentication. Please try again.",
            response.content.decode("utf-8"),
        )

    @mock.patch(
        "hidp.federated.views.authorization_code_flow.handle_authentication_callback",
        side_effect=OAuth2Error("OAuth2 error"),
    )
    def test_handles_oauth2_error(self, mock_handle_authentication_callback):
        response = self.client.get(
            reverse("hidp_oidc_client:callback", kwargs={"provider_key": "example"}),
            secure=True,
            follow=True,
        )
        self.assertTemplateUsed(response, "hidp/accounts/login.html")
        self.assertInHTML(
            "An unexpected error occurred during authentication. Please try again.",
            response.content.decode("utf-8"),
        )

    @mock.patch(
        "hidp.federated.views.authorization_code_flow.handle_authentication_callback",
        return_value=(*_VALID_AUTH_CALLBACK, None),
    )
    def test_redirect_to_register(self, mock_handle_authentication_callback):
        response = self.client.get(
            reverse("hidp_oidc_client:callback", kwargs={"provider_key": "example"}),
            secure=True,
        )
        self.assertEqual(response.status_code, HTTPStatus.FOUND)
        redirect = urllib.parse.urlparse(response.url)
        self.assertEqual(redirect.path, reverse("hidp_oidc_client:register"))
        query = urllib.parse.parse_qs(redirect.query)
        self.assertIn("token", query)
        token = query["token"][0]
        self.assertIn(token, self.client.session)

    @mock.patch(
        "hidp.federated.views.authorization_code_flow.handle_authentication_callback",
        return_value=(*_VALID_AUTH_CALLBACK, None),
    )
    def test_redirect_to_login(self, mock_handle_authentication_callback):
        user = user_factories.VerifiedUserFactory()
        models.OpenIdConnection.objects.create(
            user=user,
            provider_key="example",
            issuer_claim="example",
            subject_claim="test_subject",
        )
        response = self.client.get(
            reverse("hidp_oidc_client:callback", kwargs={"provider_key": "example"}),
            secure=True,
        )
        self.assertEqual(response.status_code, HTTPStatus.FOUND)
        redirect = urllib.parse.urlparse(response.url)
        self.assertEqual(redirect.path, reverse("hidp_oidc_client:login"))
        query = urllib.parse.parse_qs(redirect.query)
        self.assertIn("token", query)
        token = query["token"][0]
        self.assertIn(token, self.client.session)

    @mock.patch(
        "hidp.federated.views.authorization_code_flow.handle_authentication_callback",
        return_value=(*_VALID_AUTH_CALLBACK, None),
    )
    def test_must_login_to_link_account(self, mock_handle_authentication_callback):
        # A user with the same email address exists, but is not logged in
        user_factories.UserFactory(email="user@example.com")
        response = self.client.get(
            reverse("hidp_oidc_client:callback", kwargs={"provider_key": "example"}),
            secure=True,
            follow=True,
        )
        self.assertInHTML(
            "You already have an account with this email address."
            " Please log in to link your account.",
            response.content.decode("utf-8"),
        )

    @mock.patch(
        "hidp.federated.views.authorization_code_flow.handle_authentication_callback",
        return_value=(*_VALID_AUTH_CALLBACK, None),
    )
    def test_redirect_to_link_account(self, mock_handle_authentication_callback):
        # A user is logged in, but no connection exists. Continue to link account.
        user = user_factories.VerifiedUserFactory()
        self.client.force_login(user)
        response = self.client.get(
            reverse("hidp_oidc_client:callback", kwargs={"provider_key": "example"}),
            secure=True,
        )
        self.assertEqual(response.status_code, HTTPStatus.FOUND)
        redirect = urllib.parse.urlparse(response.url)
        self.assertEqual(redirect.path, reverse("hidp_oidc_client:link_account"))
        query = urllib.parse.parse_qs(redirect.query)
        self.assertIn("token", query)
        token = query["token"][0]
        self.assertIn(token, self.client.session)


class OIDCTokenDataTestMixin:
    view_name = NotImplemented
    view_class = NotImplemented

    @classmethod
    def setUpTestData(cls):
        cls.url = reverse(cls.view_name)

    def setUp(self):
        configure_oidc_clients(ExampleOIDCClient(client_id="test"))

    def _assert_invalid_token(self, *, token=None):
        response = (
            self.client.get(self.url, follow=True)
            if token is None
            else self.client.get(self.url, {"token": token}, follow=True)
        )
        self.assertTemplateUsed(response, "hidp/accounts/login.html")
        self.assertInHTML(
            "Expired or invalid token. Please try again.",
            response.content.decode("utf-8"),
        )

    def _add_oidc_data_to_session(self, *, save=True):
        session = self.client.session
        request = HttpRequest()
        request.session = session
        token = self.view_class.add_data_to_session(
            request,
            provider_key="example",
            claims={
                "iss": "example",
                "sub": "test-subject",
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

    def test_requires_token(self):
        self._assert_invalid_token()

    def test_invalid_token(self):
        self._assert_invalid_token(token="invalid")

    def test_valid_token_missing_session_data(self):
        # Do not save the session to mimic an expired session or hijacked token
        token = self._add_oidc_data_to_session(save=False)
        self._assert_invalid_token(token=token)


class TestOIDCRegistrationView(OIDCTokenDataTestMixin, TestCase):
    view_class = views.OIDCRegistrationView
    view_name = "hidp_oidc_client:register"

    def test_get_with_valid_token(self):
        token = self._add_oidc_data_to_session()
        response = self.client.get(self.url, {"token": token})
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "hidp/federated/registration.html")

    def test_post_with_valid_token(self):
        token = self._add_oidc_data_to_session()
        response = self.client.post(
            self.url + f"?token={token}",
            {"agreed_to_tos": "on"},
            follow=True,
        )
        user = UserModel.objects.filter(email="user@example.com").first()
        self.assertIsNotNone(user, msg="Expected a user to be created.")

        self.assertIsNone(user.email_verified, msg="Expected email to be unverified.")

        # Verification email sent
        self.assertEqual(len(mail.outbox), 1)
        message = mail.outbox[0]
        self.assertEqual(
            message.subject,
            "Verify your email address",
        )
        # Redirected to verification required page
        self.assertRedirects(
            response,
            reverse(
                "hidp_accounts:email_verification_required", kwargs={"token": "email"}
            ),
        )
        # Verification required page
        self.assertInHTML(
            "You need to verify your email address before you can log in.",
            response.content.decode("utf-8"),
        )


class TestOIDCLoginView(OIDCTokenDataTestMixin, TestCase):
    view_class = views.OIDCLoginView
    view_name = "hidp_oidc_client:login"

    @classmethod
    def setUpTestData(cls):
        super().setUpTestData()
        cls.user = user_factories.VerifiedUserFactory()
        cls.connection = models.OpenIdConnection.objects.create(
            user=cls.user,
            provider_key="example",
            issuer_claim="example",
            subject_claim="test-subject",
        )

    def test_valid_login(self):
        token = self._add_oidc_data_to_session()
        response = self.client.get(self.url, {"token": token})
        self.assertEqual(response.wsgi_request.user, self.user)

    def test_valid_login_inactive_user(self):
        self.user.is_active = False
        self.user.save()
        token = self._add_oidc_data_to_session()
        response = self.client.get(self.url, {"token": token}, follow=True)
        self.assertTemplateUsed(response, "hidp/accounts/login.html")
        self.assertInHTML(
            "Login failed. Invalid credentials.",
            response.content.decode("utf-8"),
        )

    def test_valid_login_unverified_user(self):
        self.user.email_verified = None
        self.user.save()
        token = self._add_oidc_data_to_session()
        response = self.client.get(self.url, {"token": token}, follow=True)

        # Verification email sent
        self.assertEqual(len(mail.outbox), 1)
        message = mail.outbox[0]
        self.assertEqual(
            message.subject,
            "Verify your email address",
        )
        # Redirected to verification required page
        self.assertRedirects(
            response,
            reverse(
                "hidp_accounts:email_verification_required", kwargs={"token": "email"}
            ),
        )
        # Verification required page
        self.assertInHTML(
            "You need to verify your email address before you can log in.",
            response.content.decode("utf-8"),
        )


class TestOIDCAccountLinkView(OIDCTokenDataTestMixin, TestCase):
    view_class = views.OIDCAccountLinkView
    view_name = "hidp_oidc_client:link_account"

    @classmethod
    def setUpTestData(cls):
        super().setUpTestData()
        cls.user = user_factories.VerifiedUserFactory()

    def setUp(self):
        super().setUp()
        self.client.force_login(self.user)

    def test_requires_login(self):
        self.client.logout()
        response = self.client.get(self.url)
        self.assertRedirects(
            response,
            f"{reverse('hidp_accounts:login')}?next={self.url}",
        )

    def test_get_with_valid_token(self):
        token = self._add_oidc_data_to_session()
        response = self.client.get(self.url, {"token": token})
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "hidp/federated/account_link.html")

    def test_post_with_valid_token(self):
        token = self._add_oidc_data_to_session()
        response = self.client.post(  # noqa: F841
            self.url + f"?token={token}",
            {"allow_link": "on"},
            follow=True,
        )
        connection = models.OpenIdConnection.objects.filter(user=self.user).first()
        self.assertIsNotNone(connection, msg="Expected connection to be created.")

        # TODO: Add assertion for message in template when message is added via query params (HIDP-147) # noqa: E501, W505
