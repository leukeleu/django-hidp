import json

from datetime import UTC, datetime, timedelta
from hashlib import sha256
from http import HTTPStatus
from urllib.parse import parse_qs, urlencode, urlsplit

from jwcrypto import jwk, jwt
from oauth2_provider.models import get_access_token_model, get_application_model

from django.conf import settings
from django.core.signing import b64_encode
from django.test import TestCase, override_settings
from django.urls import reverse
from django.utils.timezone import now as tz_now

from hidp.test.factories import user_factories

Application = get_application_model()
AccessToken = get_access_token_model()


@override_settings(REGISTRATION_ENABLED=True)
class TestOAuthFlow(TestCase):
    @classmethod
    def setUpTestData(cls):
        cls.user = user_factories.UserFactory(
            first_name="Henk", last_name="de Vries", email="henk@example.com"
        )
        # Create a public application (client), that does not keep a secret.
        #
        # * Use the Authorization Code grant type (PKCE is enabled by default).
        # * Skip authorization, this client is trusted (e.g. a first-party app).
        # * Use the RS256 algorithm for ID tokens. This allows the client to
        #   verify the token signature using the public key.
        #
        # This is the preferred setup for any (first-party) client application.
        cls.trusted_application = Application.objects.create(
            name="Happy App",
            client_id="happy-app",
            client_type=Application.CLIENT_PUBLIC,
            client_secret="",
            authorization_grant_type=Application.GRANT_AUTHORIZATION_CODE,
            skip_authorization=True,
            redirect_uris="https://127.0.0.1/",
            algorithm=Application.RS256_ALGORITHM,
        )
        cls.third_party_application = Application.objects.create(
            name="Shady App",
            client_id="shady-app",
            client_type=Application.CLIENT_PUBLIC,
            client_secret="",
            authorization_grant_type=Application.GRANT_AUTHORIZATION_CODE,
            skip_authorization=False,
            redirect_uris="https://127.0.0.1/",
            algorithm=Application.RS256_ALGORITHM,
        )

    def set_client_access_token(self, client=None, user=None, scope=""):
        """Add an access token to the test client."""
        # Utility method to add an access token to the test client, used in
        # the test methods to simulate a logged-in user.

        token = AccessToken.objects.create(
            user=user or self.user,
            scope=scope,
            expires=tz_now() + timedelta(seconds=300),
            token="secret-access-token-key",
            application=self.trusted_application,
        )
        (client or self.client).defaults["HTTP_AUTHORIZATION"] = f"Bearer {token}"

    def authorization_request(
        self, code_verifier="secret", client_id="happy-app", **oauth_params
    ):
        """Perform an authorization request."""
        # Utility method to perform an authorization request, used in the test
        # methods to simulate the authorization code grant flow.

        # PKCE challenge
        if code_verifier:
            code_challenge = b64_encode(sha256(code_verifier.encode()).digest())
        else:
            code_challenge = None

        # Authorization request: code grant + PKCE
        return self.client.get(
            "/o/authorize/",
            # Filter out None values
            {
                key: value
                for key, value in {
                    "response_type": "code",
                    "client_id": client_id,
                    "scope": "openid profile email",
                    "redirect_uri": "https://127.0.0.1/",
                    "code_challenge": code_challenge,
                    "code_challenge_method": "S256",
                    **oauth_params,
                }.items()
                if value is not None
            },
        )

    def test_authorize_authentication_required(self):
        """Authorization endpoint requires authentication."""
        # User is not logged in
        response = self.authorization_request()

        self.assertEqual(HTTPStatus.FOUND, response.status_code)
        self.assertRegex(
            response["Location"],
            r"^/login/\?next=/o/authorize/"
            r"%3Fresponse_type%3Dcode"
            r"%26client_id%3Dhappy-app"
            r"%26scope%3Dopenid%2Bprofile%2Bemail"
            r"%26redirect_uri%3Dhttps%253A%252F%252F127.0.0.1%252F"
            r"%26code_challenge%3D[a-zA-Z0-9-_]+"
            r"%26code_challenge_method%3DS256$",
        )

    def test_requires_pkce(self):
        self.client.force_login(self.user)  # User is logged in
        response = self.authorization_request(None)
        self.assertRedirects(
            response,
            "https://127.0.0.1/?error=invalid_request&error_description=Code+challenge+required.",
            fetch_redirect_response=False,
        )

    def test_code_grant_token_exchange(self):
        """Test authorization flow."""
        code_verifier = "secret"
        self.client.force_login(self.user)  # User is logged in
        response = self.authorization_request(code_verifier)

        self.assertEqual(HTTPStatus.FOUND, response.status_code)
        self.assertRegex(
            response["Location"], r"^https://127\.0\.0\.1/\?code=[A-z0-9]+$"
        )

        # Get authorization code
        code = parse_qs(urlsplit(response["Location"]).query)["code"]

        # Trade authorization code for tokens
        response = self.client.post(
            "/o/token/",
            {
                "client_id": "happy-app",
                "grant_type": "authorization_code",
                "code": code,
                "code_verifier": code_verifier,
            },
        )
        self.assertEqual(HTTPStatus.OK, response.status_code)
        self.assertEqual(
            {
                "access_token",
                "refresh_token",
                "id_token",
                "expires_in",
                "token_type",
                "scope",
            },
            set(response.json().keys()),
        )

        # Inspect id_token
        key = jwk.JWK.from_pem(
            settings.OAUTH2_PROVIDER["OIDC_RSA_PRIVATE_KEY"].encode()
        )
        id_token = jwt.JWT(jwt=response.json()["id_token"], key=key)
        claims = json.loads(id_token.claims)
        self.assertEqual(
            {
                "aud",
                "iat",
                "at_hash",
                "sub",
                "iss",
                "exp",
                "auth_time",
                "jti",
                "email_verified",
                "email",
                "family_name",
                "updated_at",
                "name",
                "given_name",
            },
            set(claims.keys()),
        )
        self.assertEqual("happy-app", claims["aud"])
        self.assertEqual(str(self.user.id), claims["sub"])

    def test_authorize_login_prompt(self):
        """Test authorization endpoint can force login prompt."""
        self.client.force_login(self.user)  # User is logged in
        response = self.authorization_request(prompt="login")

        self.assertEqual(HTTPStatus.FOUND, response.status_code)
        self.assertRegex(
            response["Location"],
            r"^/login/\?next=/o/authorize/"
            r"%3Fresponse_type%3Dcode"
            r"%26client_id%3Dhappy-app"
            r"%26scope%3Dopenid%2Bprofile%2Bemail"
            r"%26redirect_uri%3Dhttps%253A%252F%252F127.0.0.1%252F"
            r"%26code_challenge%3D[a-zA-Z0-9-_]+"
            r"%26code_challenge_method%3DS256$",
        )

    def test_authorize_prompt_none(self):
        """Test authorization endpoint can skip login prompt."""
        with self.subTest("User is not logged in"):
            response = self.authorization_request(prompt="none")
            self.assertEqual(HTTPStatus.FOUND, response.status_code)
            self.assertURLEqual(
                response["Location"], "https://127.0.0.1/?error=login_required"
            )

        with self.subTest("User is logged in"):
            self.client.force_login(self.user)
            response = self.authorization_request(prompt="none")
            self.assertEqual(HTTPStatus.FOUND, response.status_code)
            self.assertRegex(
                response["Location"], r"^https://127\.0\.0\.1/\?code=[A-z0-9]+$"
            )

        with self.subTest("Consent required"):
            # User is logged in, but consent is required
            response = self.authorization_request(prompt="none", client_id="shady-app")
            self.assertEqual(HTTPStatus.FOUND, response.status_code)
            self.assertURLEqual(
                response["Location"], "https://127.0.0.1/?error=consent_required"
            )

    def test_authorize_create_prompt(self):
        """prompt=create redirects to registration."""
        with self.subTest("No user logged in"):
            response = self.authorization_request(prompt="create")
            next_url = (
                f"{response.request['PATH_INFO']}?{response.request['QUERY_STRING']}"
            ).replace("&prompt=create", "")
            self.assertRedirects(
                response,
                (
                    f"{reverse('hidp_accounts:register')}"
                    f"?{urlencode({'next': next_url})}"
                ),
            )

        with self.subTest("User logged in"):
            self.client.force_login(self.user)
            response = self.authorization_request(prompt="create")
            next_url = (
                f"{response.request['PATH_INFO']}?{response.request['QUERY_STRING']}"
            ).replace("&prompt=create", "")
            self.assertRedirects(
                response,
                (
                    f"{reverse('hidp_accounts:register')}"
                    f"?{urlencode({'next': next_url})}"
                ),
            )

    def test_userinfo_limited_scope(self):
        self.set_client_access_token(scope="openid")
        response = self.client.get("/o/userinfo/")
        self.assertEqual(HTTPStatus.OK, response.status_code)
        userinfo = response.json()
        self.assertEqual({"sub"}, set(userinfo.keys()))
        self.assertEqual(str(self.user.id), userinfo["sub"])

    def test_userinfo_profile_scope(self):
        self.set_client_access_token(scope="openid profile")
        response = self.client.get("/o/userinfo/")
        self.assertEqual(HTTPStatus.OK, response.status_code)
        userinfo = response.json()
        self.assertEqual(
            {"sub", "name", "given_name", "family_name", "updated_at"},
            set(userinfo.keys()),
        )
        self.assertEqual("Henk de Vries", userinfo["name"])
        self.assertEqual("Henk", userinfo["given_name"])
        self.assertEqual("de Vries", userinfo["family_name"])
        # updated_at is unix time in seconds, so discard the microseconds bit
        self.assertEqual(
            self.user.last_modified.replace(microsecond=0),
            datetime.fromtimestamp(userinfo["updated_at"], tz=UTC),
        )

    def test_userinfo_email_scope(self):
        self.set_client_access_token(scope="openid email")
        response = self.client.get("/o/userinfo/")
        self.assertEqual(HTTPStatus.OK, response.status_code)
        userinfo = response.json()
        self.assertEqual({"sub", "email", "email_verified"}, set(userinfo.keys()))
        self.assertEqual(self.user.email, userinfo["email"])
        self.assertFalse(
            userinfo["email_verified"], msg="Expected email_verified to be False"
        )

    def test_userinfo_all_scopes(self):
        # Also test that setting email_verified results in the correct output
        self.user.email_verified = tz_now()
        self.user.save()
        self.set_client_access_token(scope="openid profile email")
        response = self.client.get("/o/userinfo/")
        self.assertEqual(HTTPStatus.OK, response.status_code)
        userinfo = response.json()
        self.assertEqual(
            {
                "sub",
                "name",
                "given_name",
                "family_name",
                "updated_at",
                "email",
                "email_verified",
            },
            set(userinfo.keys()),
        )
        self.assertTrue(
            userinfo["email_verified"], msg="Expected email_verified to be True"
        )
