import urllib.parse

from http import HTTPStatus
from unittest import mock

from django.contrib.auth import get_user_model
from django.core import mail
from django.http import HttpRequest
from django.test import TestCase, override_settings
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

    def test_reauthenticate_params(self):
        response = self.client.post(
            reverse(
                "hidp_oidc_client:reauthenticate", kwargs={"provider_key": "example"}
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
                # Adds prompt=login and max_age=0 to force reauthentication
                f"&prompt=login"
                f"&max_age=0"
            ),
            fetch_redirect_response=False,
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


@override_settings(REGISTRATION_ENABLED=True)
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
            " Please sign in to link your account.",
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
        self.assertEqual(redirect.path, reverse("hidp_oidc_management:link_account"))
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

    def _assert_invalid_token(self, *, token=None, method="get"):
        request_method = getattr(self.client, method)
        response = (
            request_method(self.url, follow=True)
            if token is None
            else request_method(self.url, {"token": token}, follow=True)
        )
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

    def test_post_invalid_token(self):
        self._assert_invalid_token(token="invalid", method="post")

    def test_valid_token_missing_session_data(self):
        # Do not save the session to mimic an expired session or hijacked token
        token = self._add_oidc_data_to_session(save=False)
        self._assert_invalid_token(token=token)


@override_settings(REGISTRATION_ENABLED=True)
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
        with (
            self.assertTemplateUsed("hidp/accounts/verification/email/verification_subject.txt"),
            self.assertTemplateUsed("hidp/accounts/verification/email/verification_body.txt"),
            self.assertTemplateUsed("hidp/accounts/verification/email/verification_body.html"),
        ):  # fmt: skip
            response = self.client.post(
                self.url + f"?token={token}",
                {
                    "first_name": "Firstname",
                    "last_name": "Lastname",
                    "agreed_to_tos": "on",
                },
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
            "Verification required",
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
        with (
            self.assertTemplateUsed("hidp/accounts/verification/email/verification_subject.txt"),
            self.assertTemplateUsed("hidp/accounts/verification/email/verification_body.txt"),
            self.assertTemplateUsed("hidp/accounts/verification/email/verification_body.html"),
        ):  # fmt: skip
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
            "Verification required",
            response.content.decode("utf-8"),
        )


class TestOIDCClient(ExampleOIDCClient):
    # Same as the ExampleOIDCClient, but with a different provider key.
    provider_key = "test"


class TestOIDCLinkedServicesView(TestCase):
    @classmethod
    def setUpTestData(cls):
        cls.user = user_factories.UserFactory()
        cls.user.set_unusable_password()
        cls.user.save()
        cls.oidc_linked_services_url = reverse("hidp_oidc_management:linked_services")

    def setUp(self):
        clients = [
            ExampleOIDCClient(client_id="example"),
            TestOIDCClient(client_id="test"),
        ]
        configure_oidc_clients(*clients)

    def test_login_required(self):
        """Anonymous users should be redirected to the login page."""
        response = self.client.get(self.oidc_linked_services_url)
        self.assertRedirects(
            response,
            f"{reverse('hidp_accounts:login')}?next={self.oidc_linked_services_url}",
        )

    def test_available_services(self):
        self.client.force_login(self.user)
        response = self.client.get(self.oidc_linked_services_url)

        # No services linked
        self.assertNotInHTML("Linked services", response.content.decode("utf-8"))

        # List of available services should be displayed
        self.assertInHTML(
            "Available services",
            response.content.decode("utf-8"),
        )
        for name in ("Example", "Test"):
            self.assertInHTML(
                f"<button type='submit'>Link with {name}</button>",
                response.content.decode("utf-8"),
            )

    def test_linked_one_service(self):
        models.OpenIdConnection.objects.create(
            user=self.user,
            provider_key="example",
            issuer_claim="example",
            subject_claim="test-subject",
        )

        self.client.force_login(self.user)
        response = self.client.get(self.oidc_linked_services_url)

        # Unlinking is not possible with only one service linked and no password set
        self.assertFalse(
            response.context["can_unlink"], msg="Expected can_unlink to be False."
        )

        # The linked service should be displayed
        self.assertInHTML(
            "Linked services",
            response.content.decode("utf-8"),
        )

        # Unlink option should be disabled
        self.assertInHTML(
            "<button type='submit' disabled>Unlink from Example</button>",
            response.content.decode("utf-8"),
        )

        # The remaining service should be available
        self.assertInHTML(
            "Available services",
            response.content.decode("utf-8"),
        )
        self.assertInHTML(
            "<button type='submit'>Link with Test</button>",
            response.content.decode("utf-8"),
        )

    def test_linked_all_services(self):
        models.OpenIdConnection.objects.create(
            user=self.user,
            provider_key="example",
            issuer_claim="example",
            subject_claim="test-subject",
        )
        models.OpenIdConnection.objects.create(
            user=self.user,
            provider_key="test",
            issuer_claim="example",
            subject_claim="test-subject",
        )

        self.client.force_login(self.user)
        response = self.client.get(self.oidc_linked_services_url)

        # Unlinking is possible with multiple services linked
        self.assertTrue(
            response.context["can_unlink"], msg="Expected can_unlink to be True."
        )

        self.assertInHTML(
            "Linked services",
            response.content.decode("utf-8"),
        )
        for key in ("example", "test"):
            self.assertInHTML(
                f"<button type='submit'>Unlink from {key.capitalize()}</button>",
                response.content.decode("utf-8"),
            )

        # No additional services should be available
        self.assertNotInHTML("Available services", response.content.decode("utf-8"))

    def test_linked_one_service_with_password_set(self):
        self.user.set_password("P@ssw0rd!")
        self.user.save()

        models.OpenIdConnection.objects.create(
            user=self.user,
            provider_key="example",
            issuer_claim="example",
            subject_claim="test-subject",
        )

        self.client.force_login(self.user)

        response = self.client.get(self.oidc_linked_services_url)

        # Unlinking is possible with one service linked and a password set
        self.assertTrue(
            response.context["can_unlink"], msg="Expected can_unlink to be True."
        )

        self.assertInHTML(
            "Linked services",
            response.content.decode("utf-8"),
        )
        self.assertInHTML(
            "<button type='submit'>Unlink from Example</button>",
            response.content.decode("utf-8"),
        )


class TestOIDCAccountLinkView(OIDCTokenDataTestMixin, TestCase):
    view_class = views.OIDCAccountLinkView
    view_name = "hidp_oidc_management:link_account"

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
        response = self.client.post(
            self.url + f"?token={token}",
            {"allow_link": "on"},
            follow=True,
        )
        connection = models.OpenIdConnection.objects.filter(user=self.user).first()
        self.assertIsNotNone(connection, msg="Expected connection to be created.")

        # Redirected to the done page
        self.assertRedirects(
            response,
            reverse(
                "hidp_oidc_management:link_account_done",
                kwargs={"provider_key": "example"},
            ),
        )
        self.assertTemplateUsed(response, "hidp/federated/account_link_done.html")


class TestOIDCAccountUnlinkView(TestCase):
    view_name = "hidp_oidc_management:unlink_account"

    @classmethod
    def setUpTestData(cls):
        cls.user = user_factories.VerifiedUserFactory()
        cls.url = reverse(cls.view_name, kwargs={"provider_key": "example"})
        configure_oidc_clients(ExampleOIDCClient(client_id="test"))
        cls.connection = models.OpenIdConnection.objects.create(
            user=cls.user,
            provider_key="example",
            issuer_claim="example",
            subject_claim="test-subject",
        )

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

    def test_get_with_invalid_provider(self):
        response = self.client.get(
            reverse(self.view_name, kwargs={"provider_key": "unknown"})
        )
        self.assertEqual(response.status_code, 404)

    def test_get_with_valid_provider(self):
        response = self.client.get(self.url)
        self.assertTemplateUsed(response, "hidp/federated/account_unlink.html")
        self.assertEqual(response.status_code, 200)

    def test_post_with_valid_provider(self):
        response = self.client.post(self.url, {"allow_unlink": "on"}, follow=True)

        # Redirected to the done page
        self.assertRedirects(
            response,
            reverse(
                "hidp_oidc_management:unlink_account_done",
                kwargs={"provider_key": "example"},
            ),
        )
        self.assertTemplateUsed(response, "hidp/federated/account_unlink_done.html")

    def test_delete_only_login_method(self):
        # Remove the user's password so they can only log in via OIDC
        self.user.set_unusable_password()
        self.user.save()
        self.client.force_login(self.user)
        # Attempt to unlink the only login method
        response = self.client.post(self.url, {"allow_unlink": "on"}, follow=True)
        # Form error
        self.assertTemplateUsed(response, "hidp/federated/account_unlink.html")
        self.assertFormError(
            response.context["form"],
            None,
            "You cannot unlink your only way to sign in.",
        )

    def test_valid_provider_no_connection(self):
        other_user = user_factories.VerifiedUserFactory()
        self.client.force_login(other_user)
        response = self.client.get(self.url)
        self.assertEqual(response.status_code, 404)

        response = self.client.post(self.url, {"allow_unlink": "on"})
        self.assertEqual(response.status_code, 404)
