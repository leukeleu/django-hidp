from rest_framework import exceptions as rest_framework_exceptions

from django.contrib.auth.tokens import default_token_generator
from django.test import RequestFactory, TestCase, override_settings
from django.urls import reverse
from django.utils.encoding import force_bytes
from django.utils.http import urlsafe_base64_encode

from hidp.accounts import tokens
from hidp.accounts.models import EmailChangeRequest
from hidp.api.serializers import (
    EmailChangeConfirmSerializer,
    EmailChangeSerializer,
    LoginSerializer,
    PasswordResetConfirmationSerializer,
    PasswordResetRequestSerializer,
)
from hidp.test.factories.user_factories import EmailChangeRequestFactory, UserFactory


class TestLoginSerializer(TestCase):
    @classmethod
    def setUpTestData(cls):
        cls.factory = RequestFactory()
        cls.url = reverse("api:login")
        cls.user = UserFactory()

    def make_serializer(self, username, password):
        data = {"username": username, "password": password}
        request = self.factory.post(self.url, data=data)
        return LoginSerializer(data=data, context={"request": request})

    def test_serializer_valid_credentials(self):
        """Tests that a user is authenticated when valid credentials are provided."""
        serializer = self.make_serializer(
            username=self.user.email, password="P@ssw0rd!"
        )

        self.assertTrue(serializer.is_valid())
        self.assertEqual(serializer.validated_data["user"], self.user)
        self.assertTrue(self.user.is_authenticated)

    def test_serializer_invalid_credentials(self):
        """Verify that a ValidationError is raised on invalid credentials."""
        with self.subTest("User provides invalid password"):
            serializer = self.make_serializer(
                username=self.user.email,
                password="WrongPassword!",
            )

            with self.assertRaises(rest_framework_exceptions.ValidationError):
                serializer.is_valid(raise_exception=True)

            errors = serializer.errors["non_field_errors"]
            self.assertEqual(len(errors), 1)
            self.assertEqual(str(errors[0]), "Could not authenticate")

        with self.subTest("User provides invalid email"):
            serializer = self.make_serializer(
                username="WrongEmail@email.com",
                password="P@ssw0rd!",
            )

            with self.assertRaises(rest_framework_exceptions.ValidationError):
                serializer.is_valid(raise_exception=True)

            errors = serializer.errors["non_field_errors"]
            self.assertEqual(len(errors), 1)
            self.assertEqual(str(errors[0]), "Could not authenticate")


class TestPasswordResetRequestSerializer(TestCase):
    @classmethod
    def setUpTestData(cls):
        cls.factory = RequestFactory()
        cls.url = reverse("api:password_reset_request")
        cls.user = UserFactory()

    def make_serializer(self, email):
        data = {"email": email}
        request = self.factory.post(self.url, data=data)
        return PasswordResetRequestSerializer(
            data=data, context={"request": request, "user": self.user}
        )

    def test_serializer_valid_email_active_user(self):
        """Verify that a valid email from an active user adds the user to validated data."""  # noqa: E501, W505
        serializer = self.make_serializer(email=self.user.email)

        self.assertTrue(serializer.is_valid())
        self.assertEqual(serializer.validated_data["user"], self.user)

    def test_serializer_valid_email_inactive_user(self):
        """Verify that a valid email from an inactive user results in user being None in validated data."""  # noqa: E501, W505
        self.user.is_active = False
        self.user.save()
        serializer = self.make_serializer(email=self.user.email)

        self.assertTrue(serializer.is_valid())
        self.assertEqual(serializer.validated_data["user"], None)

    def test_serializer_invalid_email(self):
        """Tests that an invalid email results in user being None in validated data."""
        serializer = self.make_serializer(email="invalid@example.com")

        self.assertTrue(serializer.is_valid())
        self.assertEqual(serializer.validated_data["user"], None)


class TestPasswordResetConfirmationSerializer(TestCase):
    @classmethod
    def setUpTestData(cls):
        cls.factory = RequestFactory()
        cls.url = reverse("api:password_reset_confirm")
        cls.user = UserFactory()

    def make_serializer(self, token, new_password, uidb64=None):
        data = {
            "token": token,
            "new_password": new_password,
            "uidb64": uidb64 or urlsafe_base64_encode(force_bytes(self.user.pk)),
        }
        request = self.factory.post(self.url, data=data)
        # PasswordResetConfirmationSerializer requires a 'request.user' in context
        request.user = self.user
        return PasswordResetConfirmationSerializer(
            data=data, context={"request": request}
        )

    def test_serializer_valid_data(self):
        """Tests that valid token and password pass validation."""
        token = default_token_generator.make_token(self.user)
        serializer = self.make_serializer(token=token, new_password="NewP@ssw0rd!")

        self.assertTrue(serializer.is_valid())

    def test_serializer_invalid_token(self):
        """Tests that an invalid token raises a ValidationError."""
        serializer = self.make_serializer(
            token="invalid-token", new_password="NewP@ssw0rd!"
        )

        with self.assertRaises(rest_framework_exceptions.ValidationError):
            serializer.is_valid(raise_exception=True)

        errors = serializer.errors["non_field_errors"]
        self.assertEqual(len(errors), 1)
        self.assertEqual(str(errors[0]), "Invalid token or user ID.")

    def test_serializer_invalid_user_id(self):
        """Tests that an invalid user id raises a ValidationError."""
        token = default_token_generator.make_token(self.user)
        serializer = self.make_serializer(
            token=token, new_password="NewP@ssw0rd!", uidb64="invalid-uidb64"
        )

        with self.assertRaises(rest_framework_exceptions.ValidationError):
            serializer.is_valid(raise_exception=True)

        errors = serializer.errors["non_field_errors"]
        self.assertEqual(len(errors), 1)
        self.assertEqual(str(errors[0]), "Invalid token or user ID.")

    def test_serializer_token_for_different_user(self):
        """Tests that a valid token for a different user raises a ValidationError for the current user."""  # noqa: E501, W505
        other_user = UserFactory()
        other_user_token = default_token_generator.make_token(other_user)
        # Use the current user's uidb64, but token for other_user
        serializer = self.make_serializer(
            token=other_user_token,
            new_password="NewP@ssw0rd!",
        )

        with self.assertRaises(rest_framework_exceptions.ValidationError):
            serializer.is_valid(raise_exception=True)

        errors = serializer.errors["non_field_errors"]
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
    def test_serializer_invalid_password(self):
        """Tests that an invalid password raises a ValidationError."""
        token = default_token_generator.make_token(self.user)
        serializer = self.make_serializer(token=token, new_password="tooshort")

        with self.assertRaises(rest_framework_exceptions.ValidationError):
            serializer.is_valid(raise_exception=True)

        errors = serializer.errors["non_field_errors"]
        self.assertEqual(len(errors), 2)
        self.assertEqual(
            str(errors[0]),
            "This password is too short. It must contain at least 10 characters.",
        )
        self.assertEqual(
            str(errors[1]), "This password does not contain any digits (0-9)."
        )


class TestEmailChangeSerializer(TestCase):
    @classmethod
    def setUpTestData(cls):
        cls.factory = RequestFactory()
        cls.url = reverse("api:email_change")
        cls.user = UserFactory()
        cls.existing_email_change_request = EmailChangeRequestFactory(user=cls.user)

    def make_serializer(self, proposed_email, password):
        data = {"proposed_email": proposed_email, "password": password}
        request = self.factory.post(self.url, data=data)
        request.user = self.user
        return EmailChangeSerializer(data=data, context={"request": request})

    def test_serializer_invalid_password(self):
        serializer = self.make_serializer(
            password="invalid", proposed_email="heisenberg@example.com"
        )
        self.assertFalse(serializer.is_valid())

    def test_serializer_current_email(self):
        serializer = self.make_serializer(
            password="P@ssw0rd!", proposed_email=self.user.email
        )
        self.assertFalse(serializer.is_valid())
        self.assertIn("proposed_email", serializer.errors)

    def test_serializer_valid(self):
        serializer = self.make_serializer(
            password="P@ssw0rd!", proposed_email="heisenberg@example.com"
        )
        self.assertTrue(serializer.is_valid())

        serializer.save()

        # Old EmailChangeRequest should be deleted
        self.assertFalse(
            EmailChangeRequest.objects.filter(
                id=self.existing_email_change_request.pk
            ).exists()
        )

        # New EmailChangeRequest should be created
        self.assertTrue(
            EmailChangeRequest.objects.filter(
                user=self.user,
                proposed_email="heisenberg@example.com",
            ).exists()
        )


class TestEmailChangeConfirmSerializer(TestCase):
    @classmethod
    def setUpTestData(cls):
        cls.factory = RequestFactory()
        cls.user = UserFactory(email="walter@example.com")
        cls.email_change_request = EmailChangeRequestFactory(
            user=cls.user, proposed_email="heisenberg@example.com"
        )
        cls.current_mail_token = tokens.email_change_token_generator.make_token(
            str(cls.email_change_request.pk), "current_email"
        )
        cls.proposed_mail_token = tokens.email_change_token_generator.make_token(
            str(cls.email_change_request.pk), "proposed_email"
        )
        cls.url = reverse(
            "api:email_change_confirm",
        )

    def make_serializer(self, confirmation_token, instance=None):
        data = {"confirmation_token": confirmation_token}
        request = self.factory.put(self.url, data=data)
        request.user = self.user
        return EmailChangeConfirmSerializer(
            data=data, context={"request": request}, instance=instance
        )

    def test_invalid_token(self):
        serializer = self.make_serializer("invalid")

        self.assertFalse(serializer.is_valid())
        self.assertIn("confirmation_token", serializer.errors)

    def test_current_email_valid_token(self):
        self.client.force_login(UserFactory())
        serializer = self.make_serializer(
            self.current_mail_token, instance=self.email_change_request
        )
        self.assertTrue(serializer.is_valid())

        serializer.save()

        self.email_change_request.refresh_from_db()
        self.assertEqual(self.email_change_request.confirmed_by_current_email, True)

        # Email address should not be changed yet
        self.user.refresh_from_db()
        self.assertEqual(self.user.email, "walter@example.com")

    def test_proposed_email_valid_token(self):
        self.client.force_login(UserFactory())
        serializer = self.make_serializer(
            self.proposed_mail_token, instance=self.email_change_request
        )
        self.assertTrue(serializer.is_valid())

        serializer.save()

        self.email_change_request.refresh_from_db()
        self.assertEqual(self.email_change_request.confirmed_by_proposed_email, True)

        # Email address should not be changed yet
        self.user.refresh_from_db()
        self.assertEqual(self.user.email, "walter@example.com")

    def test_post_second_valid_token(self):
        self.email_change_request.confirmed_by_current_email = True
        self.email_change_request.save()

        serializer = self.make_serializer(
            self.proposed_mail_token, instance=self.email_change_request
        )
        self.assertTrue(serializer.is_valid())

        serializer.save()

        self.user.refresh_from_db()
        self.assertEqual(self.user.email, "heisenberg@example.com")

        email_change_request = EmailChangeRequest.objects.filter(
            user=self.user, proposed_email="heisenberg@example.com"
        )
        self.assertTrue(email_change_request.exists())
        self.assertTrue(email_change_request.first().is_complete())

    def test_post_already_completed_request(self):
        self.email_change_request.confirmed_by_current_email = True
        self.email_change_request.confirmed_by_proposed_email = True
        self.email_change_request.save()

        serializer = self.make_serializer(
            self.proposed_mail_token, instance=self.email_change_request
        )
        self.assertTrue(serializer.is_valid())

        serializer.save()

        self.user.refresh_from_db()
        self.assertEqual(self.user.email, "heisenberg@example.com")

        email_change_request = EmailChangeRequest.objects.filter(
            user=self.user, proposed_email="heisenberg@example.com"
        )
        self.assertTrue(email_change_request.exists())
        self.assertTrue(email_change_request.first().is_complete())
