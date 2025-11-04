from rest_framework import exceptions as rest_framework_exceptions

from django.test import RequestFactory, TestCase
from django.urls import reverse

from hidp.api.constants import LoginType
from hidp.api.serializers import LoginSerializer
from hidp.test.factories.user_factories import UserFactory


class TestLoginSerializer(TestCase):
    @classmethod
    def setUpTestData(cls):
        cls.factory = RequestFactory()
        cls.url = reverse("api:login")
        cls.user = UserFactory()

    def make_serializer(self, username, password, login_type):
        data = {"username": username, "password": password, "login_type": login_type}
        request = self.factory.post(self.url, data=data)
        return LoginSerializer(data=data, context={"request": request})

    def test_serializer_valid_credentials(self):
        """Tests that a user is authenticated when valid credentials are provided."""
        serializer = self.make_serializer(
            username=self.user.email, password="P@ssw0rd!", login_type=LoginType.SESSION
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
                login_type=LoginType.SESSION,
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
                login_type=LoginType.SESSION,
            )

            with self.assertRaises(rest_framework_exceptions.ValidationError):
                serializer.is_valid(raise_exception=True)

            errors = serializer.errors["non_field_errors"]
            self.assertEqual(len(errors), 1)
            self.assertEqual(str(errors[0]), "Could not authenticate")
