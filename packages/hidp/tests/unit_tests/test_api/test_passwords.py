from http import HTTPStatus
from unittest.mock import Mock, patch

from rest_framework.test import APIClient, APITestCase, override_settings

from django.contrib.auth.tokens import default_token_generator
from django.core import mail
from django.urls import reverse
from django.utils.encoding import force_bytes
from django.utils.http import urlsafe_base64_encode

from hidp.compat.uuid7 import uuid7
from hidp.test.factories.user_factories import VerifiedUserFactory


class TestPasswordResetRequestView(APITestCase):
    @classmethod
    def setUpTestData(cls):
        cls.url = reverse("api:password_reset_request")
        cls.client = APIClient(enforce_csrf_checks=True)

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
                rf"password_reset_url/{uidb64}/[0-9a-z]+-[0-9a-f]+/",
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
            self.assertIn("set_password_url/", email.body)

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

    @patch("hidp.api.views.PasswordResetRequestMailer")
    @patch("hidp.api.views.SetPasswordMailer")
    @patch("hidp.api.views.logger")
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
                "Failed to send password reset email."
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
                "Failed to send password reset email."
            )
            self.assertEqual(response.status_code, HTTPStatus.NO_CONTENT)
            self.assertEqual(len(mail.outbox), 0)
            self.assertIsNone(response.data)


class TestPasswordResetConfirmationView(APITestCase):
    @classmethod
    def setUpTestData(cls):
        cls.url = reverse("api:password_reset_confirm")
        cls.client = APIClient(enforce_csrf_checks=True)
        cls.verified_user = VerifiedUserFactory()

    def test_password_reset_confirmation_valid(self):
        """
        Verify behaviour when a valid token, password and user ID are provided.

        - The user's password is updated
        - A changed password email is sent
        - The session hash of the initiating session has been updated
        - Other sessions are no longer valid and contain the old session hash
        - The response status code is 204 No Content
        - The response is empty
        """
        self.client.force_login(self.verified_user)
        pre_password_change_session_hash = self.verified_user.get_session_auth_hash()

        # Login the user in another session to verify that its session hash remains
        # unchanged
        client2 = APIClient(enforce_csrf_checks=True)
        client2.force_login(self.verified_user)

        new_password = "NewP@ssw0rd!"

        response = self.client.post(
            self.url,
            data={
                "token": default_token_generator.make_token(self.verified_user),
                "new_password": new_password,
                "uidb64": urlsafe_base64_encode(force_bytes(self.verified_user.pk)),
            },
        )

        self.verified_user.refresh_from_db()
        self.assertTrue(self.verified_user.check_password(new_password))

        self.assertEqual(len(mail.outbox), 1)
        email = mail.outbox[0]
        self.assertEqual("Your password has been changed", email.subject)
        self.assertEqual(email.to, [self.verified_user.email])
        self.assertIn("password_changed_url/", email.body)

        # Session that initiated the password change no longer has the old session hash
        self.assertNotEqual(
            self.client.session.get("_auth_user_hash"), pre_password_change_session_hash
        )
        # The other session still has the old session hash and is thus no longer valid
        self.assertEqual(
            client2.session.get("_auth_user_hash"), pre_password_change_session_hash
        )

        # The session that initiated the password change has the updated session hash
        self.assertEqual(
            self.client.session.get("_auth_user_hash"),
            self.verified_user.get_session_auth_hash(),
        )

        self.assertEqual(response.status_code, HTTPStatus.NO_CONTENT)
        self.assertIsNone(response.data)

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
        errors = response.json()["non_field_errors"]
        self.assertEqual(len(errors), 2)
        self.assertEqual(
            str(errors[0]),
            "This password is too short. It must contain at least 10 characters.",
        )
        self.assertEqual(
            str(errors[1]), "This password does not contain any digits (0-9)."
        )
