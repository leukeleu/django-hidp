from datetime import timedelta

from django.test import TestCase
from django.utils import timezone

from hidp.federated import forms
from hidp.test.factories import user_factories


class TestOIDCRegistrationForm(TestCase):
    def _create_form(self, data=None, first_name="Firstname", last_name="Lastname"):
        return forms.OIDCRegistrationForm(
            data=data,
            provider_key="test_provider",
            claims={
                "iss": "test_issuer",
                "sub": "test_subject",
                "email": "user@example.com",
            },
            user_info={
                "given_name": first_name,
                "family_name": last_name,
            },
        )

    def test_data_from_claims_and_user_info(self):
        """The form is populated from the OIDC claims and user info."""
        form = self._create_form()
        self.assertEqual(form.initial["email"], "user@example.com")
        self.assertEqual(form.initial["first_name"], "Firstname")
        self.assertEqual(form.initial["last_name"], "Lastname")

    def test_partial_data_from_claims_and_user_info(self):
        """The form is populated from the OIDC claims and partial user info."""
        form = self._create_form(first_name="")
        self.assertEqual(form.initial["first_name"], "")
        self.assertEqual(form.initial["last_name"], "Lastname")

    def test_name_fields_hidden_when_data_missing(self):
        """First and last name fields are hidden when data is missing."""
        form = self._create_form(first_name="", last_name="")
        self.assertNotIn("first_name", form.fields)
        self.assertNotIn("last_name", form.fields)

    def test_tos_required(self):
        """Terms of service must be agreed to."""
        form = self._create_form(data={})
        self.assertFalse(form.is_valid(), msg="Expected form to be invalid.")
        self.assertFormError(form, "agreed_to_tos", "This field is required.")

    def test_email_field_disabled(self):
        """Email field is disabled to prevent the user from changing it."""
        form = self._create_form(
            data={
                "email": "fake@example.com",
                "agreed_to_tos": "on",
                "first_name": "Firstname",
                "last_name": "Lastname",
            }
        )
        self.assertTrue(form.is_valid(), msg="Expected form to be valid.")
        self.assertEqual(form.instance.email, "user@example.com")

    def test_creates_user_and_connection(self):
        """The form creates a user and OpenIdConnection from claims and user info."""
        form = self._create_form(
            data={
                "agreed_to_tos": "on",
                "first_name": "Firstname",
                "last_name": "Lastname",
            }
        )
        self.assertTrue(form.is_valid(), msg="Expected form to be valid.")
        user = form.save()
        self.assertAlmostEqual(
            user.agreed_to_tos, timezone.now(), delta=timedelta(seconds=10)
        )
        connection = user.openid_connections.first()
        self.assertIsNotNone(connection, msg="Expected connection to be created.")
        self.assertEqual(connection.provider_key, "test_provider")
        self.assertEqual(connection.issuer_claim, "test_issuer")
        self.assertEqual(connection.subject_claim, "test_subject")


class TestOIDCAccountLinkForm(TestCase):
    @classmethod
    def setUpTestData(cls):
        cls.user = user_factories.VerifiedUserFactory()

    def test_requires_confirmation(self):
        form = forms.OIDCAccountLinkForm(
            data={},
            user=self.user,
            provider_key="test_provider",
            claims={
                "iss": "test_issuer",
                "sub": "test_subject",
            },
        )
        self.assertFormError(form, "allow_link", "This field is required.")

    def test_creates_connection(self):
        form = forms.OIDCAccountLinkForm(
            data={"allow_link": "on"},
            user=self.user,
            provider_key="test_provider",
            claims={
                "iss": "test_issuer",
                "sub": "test_subject",
            },
        )
        self.assertTrue(form.is_valid(), msg="Expected form to be valid.")
        form.save()
        connection = self.user.openid_connections.first()
        self.assertIsNotNone(connection, msg="Expected connection to be created.")
