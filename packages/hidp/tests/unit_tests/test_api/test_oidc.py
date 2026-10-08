from http import HTTPStatus
from urllib.parse import parse_qs, urlsplit

from rest_framework.test import APITestCase

from django.contrib.auth import get_user_model
from django.contrib.auth.backends import ModelBackend
from django.core import mail
from django.core.exceptions import PermissionDenied
from django.http import HttpRequest
from django.test import override_settings
from django.urls import reverse

from hidp.config import configure_oidc_clients
from hidp.federated import flows
from hidp.federated.constants import OIDC_STATES_SESSION_KEY
from hidp.federated.models import OpenIdConnection
from hidp.test.factories.user_factories import UserFactory, VerifiedUserFactory

from ..test_federated.test_providers.example import ExampleOIDCClient

UserModel = get_user_model()

CLAIMS = {
    "iss": "https://example.com",
    "sub": "example-subject",
    "email": "jesse@example.com",
    "given_name": "Jesse",
    "family_name": "Pinkman",
}


class TrustingOIDCClient(ExampleOIDCClient):
    trust_email_verified_claim = True


class RefusingBackend(ModelBackend):
    """Refuses every OIDC login, like a backend that checks a group."""

    def authenticate(self, request=None, provider_key=None, **credentials):
        if provider_key is not None:
            raise PermissionDenied


class OIDCTestCase(APITestCase):
    client_class_ = ExampleOIDCClient

    def setUp(self):
        configure_oidc_clients(self.client_class_(client_id="test"))

    def _store_token_data(self, token_generator, **claims):
        """Keep what the provider sent in the session, as the callback does."""
        session = self.client.session
        request = HttpRequest()
        request.session = session
        token = flows.store_token_data(
            request,
            token_generator,
            provider_key="example",
            claims=CLAIMS | claims,
            user_info={},
        )
        session.save()
        return token


class TestProviders(OIDCTestCase):
    def test_providers(self):
        response = self.client.get(reverse("hidp_api:oidc_providers"))

        self.assertEqual(response.status_code, HTTPStatus.OK)
        self.assertEqual(response.json(), [{"key": "example", "name": "Example"}])


class TestAuthenticate(OIDCTestCase):
    url = reverse("hidp_api:oidc_authenticate", kwargs={"provider_key": "example"})

    def test_redirect_url(self):
        response = self.client.post(
            self.url, {"next": "/somewhere/"}, format="json", secure=True
        )

        self.assertEqual(response.status_code, HTTPStatus.OK)
        redirect_url = urlsplit(response.json()["redirect_url"])
        self.assertEqual(redirect_url.netloc, "example.com")
        params = parse_qs(redirect_url.query)
        self.assertEqual(
            params["redirect_uri"], ["https://testserver/login/oidc/callback/example/"]
        )
        self.assertNotIn("prompt", params)
        state = self.client.session[OIDC_STATES_SESSION_KEY][params["state"][0]]
        self.assertEqual(state["next_url"], "/somewhere/")

    def test_reauthenticate(self):
        response = self.client.post(
            self.url, {"reauthenticate": True}, format="json", secure=True
        )

        params = parse_qs(urlsplit(response.json()["redirect_url"]).query)
        self.assertEqual(params["prompt"], ["login"])
        self.assertEqual(params["max_age"], ["0"])

    def test_next_on_another_host(self):
        response = self.client.post(
            self.url, {"next": "https://evil.example.com/"}, format="json", secure=True
        )

        self.assertEqual(response.status_code, HTTPStatus.BAD_REQUEST)
        self.assertIn("next", response.json())

    def test_unknown_provider(self):
        response = self.client.post(
            reverse("hidp_api:oidc_authenticate", kwargs={"provider_key": "unknown"}),
            format="json",
            secure=True,
        )

        self.assertEqual(response.status_code, HTTPStatus.NOT_FOUND)

    def test_requires_https(self):
        response = self.client.post(self.url, format="json")

        self.assertEqual(response.status_code, HTTPStatus.BAD_REQUEST)


@override_settings(REGISTRATION_ENABLED=True)
class TestRegistration(OIDCTestCase):
    url = reverse("hidp_api:oidc_registration")

    def _register(self, token, **data):
        return self.client.post(
            self.url, {"token": token, "agreed_to_tos": True} | data, format="json"
        )

    def test_get(self):
        token = self._store_token_data(flows.registration_token_generator)

        response = self.client.get(self.url, {"token": token})

        self.assertEqual(response.status_code, HTTPStatus.OK)
        self.assertEqual(
            response.json(),
            {
                "provider": {"key": "example", "name": "Example"},
                "email": "jesse@example.com",
                "first_name": "Jesse",
                "last_name": "Pinkman",
                "requires_name": True,
            },
        )

    def test_get_without_names(self):
        token = self._store_token_data(
            flows.registration_token_generator, given_name="", family_name=""
        )

        response = self.client.get(self.url, {"token": token})

        self.assertFalse(response.json()["requires_name"])

    def test_invalid_token(self):
        for token in ("invalid", self._store_token_data(flows.link_token_generator)):
            with self.subTest(token=token):
                response = self.client.get(self.url, {"token": token})

                self.assertEqual(response.status_code, HTTPStatus.BAD_REQUEST)
                self.assertIn("token", response.json())

    def test_register_sends_verification(self):
        token = self._store_token_data(flows.registration_token_generator)

        response = self._register(token, next="/somewhere/")

        self.assertEqual(response.status_code, HTTPStatus.UNAUTHORIZED)
        self.assertEqual(response.json()["pending"], [{"step": "email_verify"}])
        user = UserModel.objects.get(email="jesse@example.com")
        self.assertIsNone(user.email_verified)
        self.assertIsNotNone(user.agreed_to_tos)
        self.assertFalse(user.has_usable_password())
        self.assertTrue(user.openid_connections.filter(provider_key="example"))
        self.assertRegex(
            mail.outbox[0].body,
            r"http://testserver/frontend/verify/\S+/\?next=%2Fsomewhere%2F",
        )
        self.assertNotIn(token, self.client.session)

    def test_terms_are_required(self):
        token = self._store_token_data(flows.registration_token_generator)

        response = self._register(token, agreed_to_tos=False)

        self.assertEqual(response.status_code, HTTPStatus.BAD_REQUEST)
        self.assertIn("agreed_to_tos", response.json())
        self.assertFalse(UserModel.objects.filter(email="jesse@example.com").exists())

    def test_logged_in_user_cannot_register(self):
        self.client.force_login(VerifiedUserFactory())
        token = self._store_token_data(flows.registration_token_generator)

        response = self._register(token)

        self.assertEqual(response.status_code, HTTPStatus.FORBIDDEN)
        self.assertEqual(response.json()["code"], "already_authenticated")

    @override_settings(REGISTRATION_ENABLED=False)
    def test_registration_disabled(self):
        response = self._register("token")

        self.assertEqual(response.status_code, HTTPStatus.NOT_FOUND)


@override_settings(REGISTRATION_ENABLED=True)
class TestRegistrationWithVerifiedEmail(OIDCTestCase):
    client_class_ = TrustingOIDCClient
    url = reverse("hidp_api:oidc_registration")

    def _register(self):
        token = self._store_token_data(
            flows.registration_token_generator, email_verified=True
        )
        return self.client.post(
            self.url, {"token": token, "agreed_to_tos": True}, format="json"
        )

    def test_register_logs_in(self):
        response = self._register()

        self.assertEqual(response.status_code, HTTPStatus.OK)
        self.assertEqual(response.json()["user"]["email"], "jesse@example.com")
        self.assertEqual(len(mail.outbox), 0)

    @override_settings(AUTHENTICATION_BACKENDS=[f"{__name__}.RefusingBackend"])
    def test_refused_user_is_not_registered(self):
        response = self._register()

        self.assertEqual(response.status_code, HTTPStatus.FORBIDDEN)
        self.assertEqual(response.json()["code"], "invalid_credentials")
        self.assertFalse(UserModel.objects.filter(email="jesse@example.com").exists())


class TestLink(OIDCTestCase):
    url = reverse("hidp_api:oidc_link")

    def setUp(self):
        super().setUp()
        self.user = VerifiedUserFactory()
        self.client.force_login(self.user)

    def test_get(self):
        token = self._store_token_data(flows.link_token_generator)

        response = self.client.get(self.url, {"token": token})

        self.assertEqual(
            response.json(),
            {
                "provider": {"key": "example", "name": "Example"},
                "provider_email": "jesse@example.com",
                "email": self.user.email,
            },
        )

    def test_link(self):
        token = self._store_token_data(flows.link_token_generator)

        response = self.client.post(self.url, {"token": token}, format="json")

        self.assertEqual(response.status_code, HTTPStatus.NO_CONTENT)
        connection = self.user.openid_connections.get()
        self.assertEqual(connection.subject_claim, "example-subject")
        self.assertNotIn(token, self.client.session)

    def test_already_linked(self):
        OpenIdConnection.objects.create(
            user=self.user,
            provider_key="example",
            issuer_claim="https://example.com",
            subject_claim="other-subject",
        )
        token = self._store_token_data(flows.link_token_generator)

        response = self.client.post(self.url, {"token": token}, format="json")

        self.assertEqual(response.status_code, HTTPStatus.BAD_REQUEST)
        self.assertIn("non_field_errors", response.json())
        self.assertEqual(self.user.openid_connections.count(), 1)

    def test_requires_login(self):
        self.client.logout()

        response = self.client.get(self.url, {"token": "token"})

        self.assertEqual(response.status_code, HTTPStatus.FORBIDDEN)


class TestConnections(OIDCTestCase):
    def setUp(self):
        super().setUp()
        self.user = VerifiedUserFactory()
        OpenIdConnection.objects.create(
            user=self.user,
            provider_key="example",
            issuer_claim="https://example.com",
            subject_claim="example-subject",
        )
        self.client.force_login(self.user)
        self.url = reverse(
            "hidp_api:oidc_connection", kwargs={"provider_key": "example"}
        )

    def test_list(self):
        response = self.client.get(reverse("hidp_api:oidc_connections"))

        self.assertEqual(
            response.json(),
            [{"key": "example", "name": "Example", "linked": True, "can_unlink": True}],
        )

    def test_unlink(self):
        response = self.client.delete(self.url)

        self.assertEqual(response.status_code, HTTPStatus.NO_CONTENT)
        self.assertFalse(self.user.openid_connections.exists())

    def test_cannot_unlink_the_only_way_to_log_in(self):
        user = UserFactory(password=None)
        user.set_unusable_password()
        user.save()
        OpenIdConnection.objects.create(
            user=user,
            provider_key="example",
            issuer_claim="https://example.com",
            subject_claim="only-subject",
        )
        self.client.force_login(user)

        connections = self.client.get(reverse("hidp_api:oidc_connections")).json()
        response = self.client.delete(self.url)

        self.assertFalse(connections[0]["can_unlink"])
        self.assertEqual(response.status_code, HTTPStatus.FORBIDDEN)
        self.assertEqual(response.json()["code"], "only_login_method")
        self.assertTrue(user.openid_connections.exists())

    def test_unlink_a_provider_that_is_not_linked(self):
        self.user.openid_connections.all().delete()

        response = self.client.delete(self.url)

        self.assertEqual(response.status_code, HTTPStatus.NOT_FOUND)
