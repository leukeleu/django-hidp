from rest_framework import exceptions as rest_framework_exceptions

from django.contrib.auth.tokens import default_token_generator
from django.test import RequestFactory, TestCase, override_settings
from django.urls import reverse
from django.utils.encoding import force_bytes
from django.utils.http import urlsafe_base64_encode

from hidp.api.serializers import (
    LoginSerializer,
    PasswordResetConfirmationSerializer,
    PasswordResetRequestSerializer,
)
from hidp.test.factories.user_factories import UserFactory


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
        """Tests that an invalid token raises a ValidationError."""
        token = default_token_generator.make_token(self.user)
        serializer = self.make_serializer(
            token=token, new_password="NewP@ssw0rd!", uidb64="invalid-uidb64"
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
