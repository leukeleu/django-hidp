from datetime import timedelta

from oauth2_provider.models import get_access_token_model, get_application_model
from rest_framework.test import APITestCase

from django.urls import reverse
from django.utils.timezone import now as tz_now

from hidp.test.factories import user_factories

AccessToken = get_access_token_model()
Application = get_application_model()


class TestUserViewSetViaSession(APITestCase):
    @classmethod
    def setUpTestData(cls):
        cls.user = user_factories.UserFactory(first_name="Walter", last_name="White")
        cls.url = reverse("api:user-detail", kwargs={"pk": "me"})

    def setUp(self):
        self.client.force_login(self.user)

    def test_get_unauthenticated(self):
        self.client.logout()
        response = self.client.get(self.url)
        self.assertEqual(response.status_code, 403)

    def test_get_other_user_not_allowed(self):
        other_user = user_factories.UserFactory()
        self.client.force_login(other_user)

        response = self.client.get(
            reverse("api:user-detail", kwargs={"pk": self.user.pk}),
        )
        self.assertEqual(response.status_code, 404)

    def test_get(self):
        response = self.client.get(self.url)
        self.assertEqual(response.status_code, 200)
        self.assertEqual(
            {
                "first_name": "Walter",
                "last_name": "White",
            },
            response.json(),
        )

    def test_update_user_unauthenticated(self):
        self.client.logout()
        response = self.client.patch(
            self.url,
            data={"first_name": "Skyler"},
        )
        self.assertEqual(response.status_code, 403)

    def test_update_with_pk_not_allowed(self):
        response = self.client.patch(
            reverse("api:user-detail", kwargs={"pk": self.user.pk}),
            data={"first_name": "Skyler"},
        )
        self.assertEqual(response.status_code, 404)

    def test_update_other_user_not_allowed(self):
        other_user = user_factories.UserFactory()
        self.client.force_login(other_user)

        response = self.client.patch(
            reverse("api:user-detail", kwargs={"pk": self.user.pk}),
            data={"first_name": "Skyler"},
        )
        self.assertEqual(response.status_code, 404)

    def test_update_user_with_patch_without_all_required_fields(self):
        # Patch without all required fields should partially update.
        response = self.client.patch(
            self.url,
            data={"first_name": "Skyler"},
        )
        self.assertEqual(response.status_code, 200)
        self.user.refresh_from_db()
        self.assertEqual(self.user.first_name, "Skyler")
        self.assertEqual(self.user.last_name, "White")

    def test_update_user_with_patch_with_all_required_fields(self):
        # Patch with all required fields should update the user."
        response = self.client.patch(
            self.url,
            data={"first_name": "Jesse", "last_name": "Pinkman"},
        )
        self.assertEqual(response.status_code, 200)
        self.user.refresh_from_db()
        self.assertEqual(self.user.first_name, "Jesse")
        self.assertEqual(self.user.last_name, "Pinkman")

    def test_update_user_with_put_without_all_required_fields(self):
        # Put without all required fields should throw an error.
        response = self.client.put(
            self.url,
            data={"first_name": "Skyler"},
        )
        self.assertEqual(response.status_code, 400)
        self.assertEqual(
            '{"last_name":["This field is required."]}',
            response.content.decode("utf-8"),
        )
        self.user.refresh_from_db()
        self.assertEqual(self.user.first_name, "Walter")

    def test_update_user_with_put_with_all_required_fields(self):
        # Put with all required fields should update the user.
        response = self.client.put(
            self.url,
            data={"first_name": "Jesse", "last_name": "Pinkman"},
        )
        self.assertEqual(response.status_code, 200)
        self.user.refresh_from_db()
        self.assertEqual(self.user.first_name, "Jesse")
        self.assertEqual(self.user.last_name, "Pinkman")


class TestUserViewSetViaAccessToken(APITestCase):
    @classmethod
    def setUpTestData(cls):
        cls.user = user_factories.UserFactory(first_name="Walter", last_name="White")
        cls.url = reverse("api:user-detail", kwargs={"pk": "me"})
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

    def set_client_access_token(self, expires_in=300):
        """Add an access token to the test client."""
        # Utility method to add an access token to the test client, used in
        # the test methods to simulate a logged-in user.
        token = AccessToken.objects.create(
            user=self.user,
            scope="openid profile email",
            expires=tz_now() + timedelta(seconds=expires_in),
            token="secret-access-token-key",
            application=self.trusted_application,
        )
        self.client.defaults["HTTP_AUTHORIZATION"] = f"Bearer {token}"

    def test_get_with_expired_token(self):
        self.set_client_access_token(expires_in=-300)

        response = self.client.get(self.url)
        self.assertEqual(response.status_code, 403)

    def test_get_with_access_token(self):
        self.set_client_access_token()

        response = self.client.get(self.url)
        self.assertEqual(response.status_code, 200)
        self.assertEqual(
            {
                "first_name": "Walter",
                "last_name": "White",
            },
            response.json(),
        )

    def test_update_user_with_expired_token(self):
        self.set_client_access_token(expires_in=-300)

        response = self.client.patch(
            self.url,
            data={"first_name": "Skyler"},
        )
        self.assertEqual(response.status_code, 403)
        self.user.refresh_from_db()
        self.assertEqual(self.user.first_name, "Walter")
        self.assertEqual(self.user.last_name, "White")

    def test_update_user_with_access_token(self):
        self.set_client_access_token()

        response = self.client.patch(
            self.url,
            data={"first_name": "Skyler"},
        )
        self.assertEqual(response.status_code, 200)
        self.user.refresh_from_db()
        self.assertEqual(self.user.first_name, "Skyler")
        self.assertEqual(self.user.last_name, "White")
