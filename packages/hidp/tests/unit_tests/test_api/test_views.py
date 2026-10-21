from datetime import timedelta

from oauth2_provider.models import get_access_token_model, get_application_model
from rest_framework.test import APITestCase

from django.core import mail
from django.test import SimpleTestCase, override_settings
from django.urls import NoReverseMatch, reverse
from django.utils import timezone
from django.utils.timezone import now as tz_now

from hidp.accounts import tokens
from hidp.accounts.models import EmailChangeRequest
from hidp.test.factories import user_factories

AccessToken = get_access_token_model()
Application = get_application_model()


class TestUserViewViaSession(APITestCase):
    @classmethod
    def setUpTestData(cls):
        cls.user = user_factories.UserFactory(
            first_name="Walter",
            last_name="White",
            email="walter@example.com",
        )
        cls.url = reverse("hidp_api:user")

    def setUp(self):
        self.client.force_login(self.user)

    def test_get_unauthenticated(self):
        self.client.logout()
        response = self.client.get(self.url)
        self.assertEqual(response.status_code, 403)

    def test_get(self):
        response = self.client.get(self.url)
        self.assertEqual(response.status_code, 200)
        self.assertEqual(
            {
                "id": str(self.user.id),
                "first_name": "Walter",
                "last_name": "White",
                "email": "walter@example.com",
                "has_usable_password": True,
            },
            response.json(),
        )

    def test_update_user_unauthenticated(self):
        self.client.logout()
        response = self.client.patch(self.url, data={"first_name": "Skyler"})
        self.assertEqual(response.status_code, 403)

    def test_update_user_with_patch_with_read_only_field(self):
        response = self.client.patch(
            self.url,
            data={"email": "skyler@example.com", "is_superuser": True},
        )
        self.assertEqual(response.status_code, 200)
        self.user.refresh_from_db()
        self.assertEqual(self.user.email, "walter@example.com")
        self.assertFalse(self.user.is_superuser)

    def test_update_user_with_patch(self):
        response = self.client.patch(self.url, data={"first_name": "Skyler"})
        self.assertEqual(response.status_code, 200)
        self.user.refresh_from_db()
        self.assertEqual(self.user.first_name, "Skyler")
        self.assertEqual(self.user.last_name, "White")

    def test_update_user_with_blank_name(self):
        response = self.client.patch(self.url, data={"first_name": ""})
        self.assertEqual(response.status_code, 400)
        self.assertIn("first_name", response.json())

    def test_put_not_allowed(self):
        response = self.client.put(
            self.url, data={"first_name": "Jesse", "last_name": "Pinkman"}
        )
        self.assertEqual(response.status_code, 405)


class TestUserViewViaAccessToken(APITestCase):
    @classmethod
    def setUpTestData(cls):
        cls.user = user_factories.UserFactory(
            first_name="Walter", last_name="White", email="walter@example.com"
        )
        cls.url = reverse("hidp_api:user")
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

    def set_client_access_token(self, expires_in=300, scope="openid profile email"):
        """Add an access token to the test client."""
        # Utility method to add an access token to the test client, used in
        # the test methods to simulate a logged-in user.
        token = AccessToken.objects.create(
            user=self.user,
            scope=scope,
            expires=tz_now() + timedelta(seconds=expires_in),
            token="secret-access-token-key",
            application=self.trusted_application,
        )
        self.client.defaults["HTTP_AUTHORIZATION"] = f"Bearer {token.token}"

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
                "id": str(self.user.id),
                "first_name": "Walter",
                "last_name": "White",
                "email": "walter@example.com",
                "has_usable_password": True,
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

    def test_get_without_profile_and_email_scopes(self):
        self.set_client_access_token(scope="openid")

        response = self.client.get(self.url)
        self.assertEqual(response.status_code, 403)

    def test_update_user_with_access_token(self):
        self.set_client_access_token()

        response = self.client.patch(
            self.url,
            data={"first_name": "Skyler"},
        )
        self.assertEqual(response.status_code, 403)
        self.user.refresh_from_db()
        self.assertEqual(self.user.first_name, "Walter")

    def test_response_is_not_cached(self):
        self.set_client_access_token()

        response = self.client.get(self.url)
        self.assertIn("no-store", response["Cache-Control"])

    def test_get_with_only_profile_scope(self):
        self.set_client_access_token(scope="openid profile")

        response = self.client.get(self.url)
        self.assertEqual(response.status_code, 403)

    def test_get_for_inactive_user(self):
        self.user.is_active = False
        self.user.save(update_fields=["is_active"])
        self.set_client_access_token()

        response = self.client.get(self.url)
        self.assertEqual(response.status_code, 403)

    def test_access_token_does_not_authenticate_other_endpoints(self):
        self.set_client_access_token()

        response = self.client.post(
            reverse("hidp_api:password_change"),
            {"old_password": "P@ssw0rd!", "new_password": "N3wP@ssw0rd!"},
            format="json",
        )
        self.assertEqual(response.status_code, 403)

    def test_hidp_urls_mount_the_user_endpoint(self):
        self.set_client_access_token()

        with override_settings(ROOT_URLCONF="hidp.config.urls"):
            url = reverse("api:user")
            response = self.client.get(url)

        self.assertEqual(url, "/api/users/me/")
        self.assertEqual(response.status_code, 200)


@override_settings(ROOT_URLCONF="hidp.config.urls")
class TestHidpUrls(SimpleTestCase):
    """The HIdP URLs mount the user endpoint, but not the headless API."""

    def test_headless_api_is_not_mounted(self):
        with self.assertRaises(NoReverseMatch):
            reverse("hidp_api:login")


class TestEmailChangeView(APITestCase):
    @classmethod
    def setUpTestData(cls):
        cls.user = user_factories.UserFactory(
            first_name="Walter", last_name="White", email="walter@example.com"
        )
        cls.url = reverse("hidp_api:email_change")

    def setUp(self):
        self.client.force_login(self.user)

    def test_post_unauthenticated(self):
        self.client.logout()
        response = self.client.post(self.url)

        self.assertEqual(response.status_code, 403)

    def test_post_current_email(self):
        response = self.client.post(
            self.url,
            {"proposed_email": "walter@example.com", "password": "P@ssw0rd!"},
            format="json",
        )

        self.assertEqual(response.status_code, 400)
        self.assertFalse(EmailChangeRequest.objects.exists())
        self.assertEqual(len(mail.outbox), 0)

    def test_post_user_without_password_requests_email_change(self):
        self.user.set_unusable_password()
        self.user.save()

        self.client.force_login(self.user)
        response = self.client.post(
            self.url,
            {
                "password": "P@ssw0rd!",
                "proposed_email": "heisenberg@example.com",
            },
        )

        self.assertEqual(403, response.status_code)
        self.assertEqual(response.json()["code"], "password_not_set")

    def test_post_user_with_wrong_password_requests_email_change(self):
        self.user.save()

        self.client.force_login(self.user)
        response = self.client.post(
            self.url,
            {
                "password": "SayMyName",
                "proposed_email": "heisenberg@example.com",
            },
        )

        self.assertEqual(400, response.status_code)
        self.assertIn("password", response.json())

    def test_post_create_email_change_request(self):
        response = self.client.post(
            self.url,
            {
                "proposed_email": "heisenberg@example.com",
                "password": "P@ssw0rd!",
            },
        )

        self.assertEqual(201, response.status_code)

        self.assertTrue(
            EmailChangeRequest.objects.filter(
                user=self.user,
                proposed_email="heisenberg@example.com",
                confirmed_by_proposed_email=False,
                confirmed_by_current_email=False,
            ).exists()
        )

        self.assertEqual(len(mail.outbox), 2)

        message = mail.outbox[0]
        self.assertEqual(
            message.subject,
            "Confirm your email change request",
        )
        self.assertEqual(message.to, [self.user.email])
        self.assertRegex(
            message.body,
            # Matches the email change confirmation URL:
            # http://testserver/frontend/change-email/eyJ1dWlkIjoiMDE5MjZiNGYtODQ0Zi03MjRmLWE2YjQtMWQxYWEyYTU5OTgwIiwicmVjaXBpZW50IjoiY3VycmVudF9lbWFpbCJ9:1sy5S2:R7m51osUdabcMuOGXZRq7MabESIqKGl_mX2jO-TAcj8/
            r"http://testserver/frontend/change-email/[0-9A-Za-z]+:[0-9a-zA-Z]+:[0-9A-Za-z_-]+/",
        )
        self.assertIn(
            "http://testserver/frontend/change-email/cancel/",
            message.body,
        )

        # Email should be sent to proposed email
        message = mail.outbox[1]
        self.assertEqual(
            message.subject,
            "Confirm your email change request",
        )
        self.assertEqual(message.to, ["heisenberg@example.com"])
        self.assertRegex(
            message.body,
            # Matches the email change confirmation URL:
            # http://testserver/frontend/change-email/eyJ1dWlkIjoiMDE5MjZiNGYtODQ0Zi03MjRmLWE2YjQtMWQxYWEyYTU5OTgwIiwicmVjaXBpZW50IjoiY3VycmVudF9lbWFpbCJ9:1sy5S2:R7m51osUdabcMuOGXZRq7MabESIqKGl_mX2jO-TAcj8/
            r"http://testserver/frontend/change-email/[0-9A-Za-z]+:[0-9a-zA-Z]+:[0-9A-Za-z_-]+/",
        )
        self.assertIn(
            "http://testserver/frontend/change-email/cancel/",
            message.body,
        )

    def test_post_email_change_proposed_email_exists(self):
        user_factories.UserFactory(email="existing@example.com")

        response = self.client.post(
            self.url,
            {
                "password": "P@ssw0rd!",
                "proposed_email": "existing@example.com",
            },
            follow=True,
        )

        self.assertEqual(201, response.status_code)

        # EmailChangeRequest should be created
        self.assertTrue(
            EmailChangeRequest.objects.filter(
                user=self.user,
                proposed_email="existing@example.com",
            ).exists()
        )

        # Email should be sent to current email
        self.assertEqual(len(mail.outbox), 2)

        message = mail.outbox[0]
        self.assertEqual(
            message.subject,
            "Confirm your email change request",
        )
        self.assertEqual(message.to, [self.user.email])
        self.assertRegex(
            message.body,
            # Matches the email change confirmation URL:
            # http://testserver/frontend/change-email/eyJ1dWlkIjoiMDE5MjZiNGYtODQ0Zi03MjRmLWE2YjQtMWQxYWEyYTU5OTgwIiwicmVjaXBpZW50IjoiY3VycmVudF9lbWFpbCJ9:1sy5S2:R7m51osUdabcMuOGXZRq7MabESIqKGl_mX2jO-TAcj8/
            r"http://testserver/frontend/change-email/[0-9A-Za-z]+:[0-9a-zA-Z]+:[0-9A-Za-z_-]+/",
        )
        self.assertIn(
            "http://testserver/frontend/change-email/cancel/",
            message.body,
        )

        # A different email should be sent to proposed email
        message = mail.outbox[1]
        self.assertEqual(
            message.subject,
            "Email change request",
        )
        self.assertEqual(message.to, ["existing@example.com"])
        self.assertIn(
            "However, you already have an account that uses existing@example.com",
            message.body,
        )
        self.assertIn(
            "http://testserver/frontend/change-email/cancel/",
            message.body,
        )

    def test_post_proposed_email_user_inactive(self):
        inactive_user = user_factories.UserFactory(is_active=False)

        response = self.client.post(
            self.url,
            {
                "password": "P@ssw0rd!",
                "proposed_email": inactive_user.email,
            },
        )

        self.assertEqual(201, response.status_code)

        # Email should be sent to current email, but not to proposed email (inactive)
        self.assertEqual(len(mail.outbox), 1)

        message = mail.outbox[0]
        self.assertEqual(
            message.subject,
            "Confirm your email change request",
        )
        self.assertEqual(message.to, [self.user.email])

    def test_delete_unauthenticated(self):
        self.client.logout()
        response = self.client.delete(self.url)

        self.assertEqual(response.status_code, 403)

    def test_delete_no_change_request(self):
        response = self.client.delete(self.url)
        self.assertEqual(response.status_code, 404)

    def test_delete_completed_change_request(self):
        email_change_request = user_factories.EmailChangeRequestFactory(user=self.user)
        email_change_request.confirmed_by_current_email = True
        email_change_request.confirmed_by_proposed_email = True
        email_change_request.save()

        response = self.client.delete(self.url)
        self.assertEqual(response.status_code, 404)

    def test_delete_expired_change_request(self):
        email_change_request = user_factories.EmailChangeRequestFactory(user=self.user)

        # by default the EmailChangeTokenGenerator is used which has a timeout of 1 day
        email_change_request.created_at = timezone.now() - timezone.timedelta(days=8)
        email_change_request.save()

        response = self.client.delete(self.url)
        self.assertEqual(response.status_code, 404)

    def test_delete(self):
        user_factories.EmailChangeRequestFactory(user=self.user)
        response = self.client.delete(self.url)
        self.assertEqual(response.status_code, 204)

        self.assertFalse(
            EmailChangeRequest.objects.filter(
                user=self.user,
            ).exists()
        )


class TestEmailChangeConfirmView(APITestCase):
    @classmethod
    def setUpTestData(cls):
        cls.user = user_factories.UserFactory(email="walter@example.com")
        cls.url = reverse("hidp_api:email_change_confirm")
        cls.email_change_request = user_factories.EmailChangeRequestFactory(
            user=cls.user, proposed_email="heisenberg@example.com"
        )
        cls.current_mail_token = tokens.email_change_token_generator.make_token(
            str(cls.email_change_request.pk), "current_email"
        )
        cls.proposed_mail_token = tokens.email_change_token_generator.make_token(
            str(cls.email_change_request.pk), "proposed_email"
        )

    def setUp(self):
        self.client.force_login(self.user)

    def test_unauthenticated_user(self):
        self.client.logout()
        response = self.client.post(self.url, data={"token": self.current_mail_token})

        self.assertEqual(403, response.status_code)

    def test_valid_token_wrong_user(self):
        self.client.force_login(user_factories.UserFactory())
        response = self.client.post(self.url, data={"token": self.current_mail_token})

        self.assertEqual(400, response.status_code)
        self.assertIn("token", response.json())

    def test_already_confirmed(self):
        self.email_change_request.confirmed_by_current_email = True
        self.email_change_request.save()
        response = self.client.post(self.url, data={"token": self.current_mail_token})

        self.assertEqual(400, response.status_code)
        self.assertIn("token", response.json())

    def test_current_email_valid_token(self):
        response = self.client.post(self.url, data={"token": self.current_mail_token})

        self.assertEqual(200, response.status_code)
        self.assertEqual(
            {
                "current_email": "walter@example.com",
                "proposed_email": "heisenberg@example.com",
                "confirmed_by_current_email": True,
                "confirmed_by_proposed_email": False,
            },
            response.json(),
        )

        self.email_change_request.refresh_from_db()
        self.assertEqual(self.email_change_request.confirmed_by_current_email, True)

        # Email address should not be changed yet
        self.user.refresh_from_db()
        self.assertEqual(self.user.email, "walter@example.com")

        # Email changed mail should not be sent yet
        self.assertEqual(len(mail.outbox), 0)

    def test_proposed_email_valid_token(self):
        response = self.client.post(self.url, data={"token": self.proposed_mail_token})

        self.assertEqual(200, response.status_code)
        self.assertEqual(
            {
                "current_email": "walter@example.com",
                "proposed_email": "heisenberg@example.com",
                "confirmed_by_current_email": False,
                "confirmed_by_proposed_email": True,
            },
            response.json(),
        )

        self.email_change_request.refresh_from_db()
        self.assertEqual(self.email_change_request.confirmed_by_proposed_email, True)

        # Email address should not be changed yet
        self.user.refresh_from_db()
        self.assertEqual(self.user.email, "walter@example.com")

        # Email changed mail should not be sent yet
        self.assertEqual(len(mail.outbox), 0)

    def test_post_second_valid_token(self):
        self.email_change_request.confirmed_by_current_email = True
        self.email_change_request.save()

        response = self.client.post(self.url, data={"token": self.proposed_mail_token})

        self.assertEqual(200, response.status_code)
        self.assertEqual(
            {
                "current_email": "walter@example.com",
                "proposed_email": "heisenberg@example.com",
                "confirmed_by_current_email": True,
                "confirmed_by_proposed_email": True,
            },
            response.json(),
        )

        self.user.refresh_from_db()
        self.assertEqual(self.user.email, "heisenberg@example.com")

        email_change_request = EmailChangeRequest.objects.filter(
            user=self.user, proposed_email="heisenberg@example.com"
        )
        self.assertTrue(email_change_request.exists())
        self.assertTrue(email_change_request.first().is_complete())

        # Email changed mail should be sent
        self.assertEqual(len(mail.outbox), 1)
        self.assertEqual(
            "Your account email address has been changed",
            mail.outbox[0].subject,
        )
        self.assertEqual(
            mail.outbox[0].to,
            ["walter@example.com", "heisenberg@example.com"],
        )

    def test_post_proposed_email_already_exists(self):
        # Should only happen if an account was created with the proposed email
        # address after email change request was made.
        user_factories.UserFactory(email="heisenberg@example.com")
        self.email_change_request.confirmed_by_current_email = True
        self.email_change_request.save()

        response = self.client.post(self.url, data={"token": self.proposed_mail_token})
        self.assertEqual(400, response.status_code)
        self.assertEqual(
            response.json(),
            {
                "non_field_errors": [
                    (
                        "Sorry, changing your email address is not possible because"
                        " an account with this email address already exists."
                    )
                ]
            },
        )

    def test_post_already_completed_request(self):
        self.email_change_request.confirmed_by_current_email = True
        self.email_change_request.confirmed_by_proposed_email = True
        self.email_change_request.save()

        response = self.client.post(self.url, data={"token": self.current_mail_token})

        self.assertEqual(400, response.status_code)
        self.assertIn("token", response.json())
