from http import HTTPStatus
from unittest.mock import Mock, patch

from rest_framework.test import APIClient, APITestCase, override_settings

from django.contrib.auth.tokens import default_token_generator
from django.core import mail
from django.urls import reverse
from django.utils.encoding import force_bytes
from django.utils.http import urlsafe_base64_encode

from hidp.api.views import PasswordResetRequestView
from hidp.compat.uuid7 import uuid7
from hidp.test.factories.user_factories import VerifiedUserFactory


class TestPasswordResetRequestView(APITestCase):
    @classmethod
    def setUpTestData(cls):
        cls.url = reverse("hidp_api:password_reset_request")

    def test_password_reset_request_valid_email(self):
        """
        Verify behaviour when a valid email is provided.

        - A password reset mail is sent
        - The correct password reset mail is sent with the correct URL
        - The response status code is 204 No Content
        - The response is empty
        """
        user = VerifiedUserFactory()

        with self.subTest("User has usable password"):
            response = self.client.post(
                self.url,
                data={
                    "email": user.email,
                },
            )

            self.assertEqual(len(mail.outbox), 1)
            email = mail.outbox[0]
            self.assertEqual("Reset your password", email.subject)
            self.assertEqual(email.to, [user.email])
            uidb64 = urlsafe_base64_encode(force_bytes(user.pk))
            self.assertRegex(
                email.body,
                # Matches the password reset URL:
                # password_reset_url/MDE5MTkyY2UtODE0Yy03NjNlLTlhMGUtMmM1ODk3MGNkYTFj/cced4c-9a0766ea185039a6d293ff660c04007e/  # noqa: E501, W505
                rf"http://testserver/frontend/reset/{uidb64}/[0-9a-z]+-[0-9a-f]+/",
            )

            self.assertEqual(response.status_code, HTTPStatus.NO_CONTENT)
            self.assertIsNone(response.data)

        mail.outbox = []

        with self.subTest("User has unusable password"):
            user.set_unusable_password()
            user.save()
            response = self.client.post(
                self.url,
                data={
                    "email": user.email,
                },
            )

            self.assertEqual(len(mail.outbox), 1)
            email = mail.outbox[0]
            self.assertEqual("Set a password", email.subject)
            self.assertEqual(email.to, [user.email])
            self.assertIn("http://testserver/frontend/set-password/", email.body)

            self.assertEqual(response.status_code, HTTPStatus.NO_CONTENT)
            self.assertIsNone(response.data)

    def test_password_reset_request_invalid_email(self):
        """
        Verify behavior when an invalid email is provided.

        - No password reset mail is sent
        - The response status code is 204 No Content
        - The response is empty
        """
        response = self.client.post(
            self.url,
            data={
                "email": "invalid@example.com",
            },
        )

        self.assertEqual(response.status_code, HTTPStatus.NO_CONTENT)
        self.assertEqual(len(mail.outbox), 0)
        self.assertIsNone(response.data)

    @patch.object(PasswordResetRequestView, "password_reset_request_mailer")
    @patch.object(PasswordResetRequestView, "set_password_mailer")
    @patch("hidp.accounts.flows.logger")
    def test_password_reset_request_mailer_raises_exception(
        self, mock_logger, mock_set_password_mailer, mock_password_reset_mailer
    ):
        """
        Verify behaviour when sending a password request email raises an exception.

        - The exception is logged
        - No password reset mail is sent
        - The response status code is 204 No Content
        - The response is empty
        """
        user = VerifiedUserFactory()

        with self.subTest("User has usable password"):
            mock_instance = Mock()
            mock_instance.send.side_effect = Exception()
            mock_password_reset_mailer.return_value = mock_instance
            response = self.client.post(
                self.url,
                data={
                    "email": user.email,
                },
            )

            mock_logger.exception.assert_called_with(
                "Failed to send password (re)set email."
            )
            self.assertEqual(response.status_code, HTTPStatus.NO_CONTENT)
            self.assertEqual(len(mail.outbox), 0)
            self.assertIsNone(response.data)

        mock_logger.reset_mock()

        with self.subTest("User has unusable password"):
            user.set_unusable_password()
            user.save()

            mock_instance = Mock()
            mock_instance.send.side_effect = Exception()
            mock_set_password_mailer.return_value = mock_instance

            response = self.client.post(
                self.url,
                data={
                    "email": user.email,
                },
            )

            mock_logger.exception.assert_called_with(
                "Failed to send password (re)set email."
            )
            self.assertEqual(response.status_code, HTTPStatus.NO_CONTENT)
            self.assertEqual(len(mail.outbox), 0)
            self.assertIsNone(response.data)

    def test_password_reset_request_inactive_user(self):
        user = VerifiedUserFactory(is_active=False)

        response = self.client.post(self.url, {"email": user.email}, format="json")

        self.assertEqual(response.status_code, HTTPStatus.NO_CONTENT)
        self.assertEqual(len(mail.outbox), 0)


class TestPasswordResetConfirmationView(APITestCase):
    @classmethod
    def setUpTestData(cls):
        cls.url = reverse("hidp_api:password_reset_confirm")
        cls.verified_user = VerifiedUserFactory()

    def test_password_reset_confirmation_valid(self):
        """
        Verify behaviour when a valid token, password and user ID are provided.

        - The request does not need to be authenticated
        - The user's password is updated
        - A changed password email is sent
        - Existing sessions of the user are no longer valid
        - The requesting session is not logged in
        - The response status code is 204 No Content
        """
        other_client = APIClient()
        other_client.force_login(self.verified_user)
        new_password = "NewP@ssw0rd!"

        response = self.client.post(
            self.url,
            data={
                "token": default_token_generator.make_token(self.verified_user),
                "new_password": new_password,
                "uidb64": urlsafe_base64_encode(force_bytes(self.verified_user.pk)),
            },
        )

        self.assertEqual(response.status_code, HTTPStatus.NO_CONTENT)
        self.assertIsNone(response.data)

        self.verified_user.refresh_from_db()
        self.assertTrue(self.verified_user.check_password(new_password))

        self.assertEqual(len(mail.outbox), 1)
        email = mail.outbox[0]
        self.assertEqual("Your password has been changed", email.subject)
        self.assertEqual(email.to, [self.verified_user.email])
        self.assertIn("http://testserver/frontend/reset/", email.body)

        self.assertNotIn("_auth_user_id", self.client.session)
        me_response = other_client.get(reverse("hidp_api:user"))
        self.assertEqual(me_response.status_code, HTTPStatus.FORBIDDEN)

    def test_password_reset_confirmation_token_is_single_use(self):
        data = {
            "token": default_token_generator.make_token(self.verified_user),
            "new_password": "NewP@ssw0rd!",
            "uidb64": urlsafe_base64_encode(force_bytes(self.verified_user.pk)),
        }
        self.client.post(self.url, data=data)

        response = self.client.post(
            self.url, data=data | {"new_password": "0therP@ss!"}
        )

        self.assertEqual(response.status_code, HTTPStatus.BAD_REQUEST)
        self.verified_user.refresh_from_db()
        self.assertTrue(self.verified_user.check_password("NewP@ssw0rd!"))

    def test_password_reset_confirmation_invalid_token(self):
        """
        Verify behavior when an invalid token is provided.

        - The user's password remains unchanged
        - Session hash remains unchanged
        - The response status code is 400 Bad Request
        - The response contains the appropriate error message
        """
        self.client.force_login(self.verified_user)
        pre_password_change_session_hash = self.verified_user.get_session_auth_hash()

        response = self.client.post(
            self.url,
            data={
                "token": "invalid-token",
                "new_password": "NewP@ssw0rd!",
                "uidb64": urlsafe_base64_encode(force_bytes(self.verified_user.pk)),
            },
        )

        self.verified_user.refresh_from_db()
        self.assertTrue(self.verified_user.check_password("P@ssw0rd!"))
        self.assertEqual(
            self.verified_user.get_session_auth_hash(), pre_password_change_session_hash
        )

        self.assertEqual(response.status_code, HTTPStatus.BAD_REQUEST)
        errors = response.json()["non_field_errors"]
        self.assertEqual(len(errors), 1)
        self.assertEqual(str(errors[0]), "Invalid token or user ID.")

    def test_password_reset_confirmation_token_of_another_user(self):
        other_user = VerifiedUserFactory()

        response = self.client.post(
            self.url,
            {
                "token": default_token_generator.make_token(self.verified_user),
                "uidb64": urlsafe_base64_encode(force_bytes(other_user.pk)),
                "new_password": "NewP@ssw0rd!",
            },
            format="json",
        )

        self.assertEqual(response.status_code, HTTPStatus.BAD_REQUEST)
        other_user.refresh_from_db()
        self.assertTrue(other_user.check_password("P@ssw0rd!"))

    def test_password_reset_confirmation_invalid_user_id(self):
        """
        Verify behavior when an invalid user ID is provided.

        - The user's password remains unchanged
        - Session hash remains unchanged
        - The response status code is 400 Bad Request
        - The response contains the appropriate error message
        """
        self.client.force_login(self.verified_user)
        pre_password_change_session_hash = self.verified_user.get_session_auth_hash()

        token = default_token_generator.make_token(self.verified_user)
        response = self.client.post(
            self.url,
            data={
                "token": token,
                "new_password": "NewP@ssw0rd!",
                "uidb64": urlsafe_base64_encode(force_bytes(uuid7())),
            },
        )

        self.assertTrue(self.verified_user.check_password("P@ssw0rd!"))
        self.assertEqual(
            self.verified_user.get_session_auth_hash(), pre_password_change_session_hash
        )

        self.assertEqual(response.status_code, HTTPStatus.BAD_REQUEST)
        errors = response.json()["non_field_errors"]
        self.assertEqual(len(errors), 1)
        self.assertEqual(str(errors[0]), "Invalid token or user ID.")

    @override_settings(
        AUTH_PASSWORD_VALIDATORS=[
            {
                "NAME": "django.contrib.auth.password_validation.MinimumLengthValidator",  # noqa: E501
                "OPTIONS": {
                    "min_length": 10,
                },
            },
            {
                "NAME": "hidp.accounts.password_validation.DigitValidator",
            },
        ]
    )
    def test_password_reset_confirmation_invalid_password(self):
        """
        Verify behavior when an invalid password is provided.

        - The user's password remains unchanged
        - Session hash remains unchanged
        - The response status code is 400 Bad Request
        - The response contains the appropriate error message
        """
        self.client.force_login(self.verified_user)
        pre_password_change_session_hash = self.verified_user.get_session_auth_hash()

        token = default_token_generator.make_token(self.verified_user)
        response = self.client.post(
            self.url,
            data={
                "token": token,
                "new_password": "tooshort",
                "uidb64": urlsafe_base64_encode(force_bytes(self.verified_user.pk)),
            },
        )

        self.assertTrue(self.verified_user.check_password("P@ssw0rd!"))
        self.assertEqual(
            self.verified_user.get_session_auth_hash(), pre_password_change_session_hash
        )

        self.assertEqual(response.status_code, HTTPStatus.BAD_REQUEST)
        errors = response.json()["new_password"]
        self.assertEqual(len(errors), 2)
        self.assertEqual(
            str(errors[0]),
            "This password is too short. It must contain at least 10 characters.",
        )
        self.assertEqual(
            str(errors[1]), "This password does not contain any digits (0-9)."
        )
