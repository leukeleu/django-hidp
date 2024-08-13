from http import HTTPStatus

from django.contrib.auth import get_user_model
from django.core import mail
from django.test import TransactionTestCase, override_settings
from django.urls import reverse
from django.utils import timezone

from hidp.accounts.email_verification import get_email_verification_required_url
from hidp.accounts.forms import UserCreationForm
from hidp.test.factories import user_factories

User = get_user_model()


@override_settings(
    LANGUAGE_CODE="en",
)
class TestRegistrationView(TransactionTestCase):
    def setUp(self):
        self.test_user = user_factories.UserFactory(email="user@example.com")
        self.signup_url = reverse("hidp_accounts:register")

    def test_get(self):
        """The registration form should be displayed."""
        response = self.client.get(self.signup_url)
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "accounts/register.html")
        self.assertIn("form", response.context)
        self.assertIsInstance(response.context["form"], UserCreationForm)

    def test_get_tos(self):
        """The terms of service should be displayed."""
        response = self.client.get(reverse("hidp_accounts:tos"))
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "accounts/tos.html")

    def test_tos_required(self):
        """The user should agree to the terms of service."""
        response = self.client.post(
            self.signup_url,
            {
                "email": "test@example.com",
                "password1": "P@ssw0rd!",
                "password2": "P@ssw0rd!",
            },
        )
        self.assertFormError(
            response.context["form"], "agreed_to_tos", "This field is required."
        )

    def test_valid_registration(self):
        """A new user should be created and logged in."""
        response = self.client.post(
            self.signup_url,
            {
                "email": "test@example.com",
                "password1": "P@ssw0rd!",
                "password2": "P@ssw0rd!",
                "agreed_to_tos": "on",
            },
            follow=True,
        )
        self.assertTrue(
            User.objects.filter(email="test@example.com").exists(),
            msg="Expected user to be created",
        )
        user = User.objects.get(email="test@example.com")
        # Agreed to TOS
        self.assertAlmostEqual(
            timezone.now(),
            user.agreed_to_tos,
            delta=timezone.timedelta(seconds=10),
        )
        # Verification email sent
        self.assertEqual(len(mail.outbox), 1)
        message = mail.outbox[0]
        self.assertEqual(
            message.subject,
            "Verify your email address",
        )
        # Redirected to verification required page
        self.assertRedirects(
            response,
            get_email_verification_required_url(user),
        )
        # Verification required page
        self.assertInHTML(
            "You need to verify your email address before you can log in.",
            response.content.decode("utf-8"),
        )

    def test_valid_registration_safe_next_param(self):
        response = self.client.post(
            self.signup_url,
            {
                "email": "test@example.com",
                "password1": "P@ssw0rd!",
                "password2": "P@ssw0rd!",
                "agreed_to_tos": "on",
                "next": "/example/",
            },
        )
        self.assertTrue(
            User.objects.filter(email="test@example.com").exists(),
            msg="Expected user to be created",
        )
        user = User.objects.get(email="test@example.com")
        # Redirected to verification required page
        self.assertRedirects(
            response,
            get_email_verification_required_url(user, next_url="/example/"),
        )

    def test_valid_registration_unsafe_next_param(self):
        response = self.client.post(
            self.signup_url,
            {
                "email": "test@example.com",
                "password1": "P@ssw0rd!",
                "password2": "P@ssw0rd!",
                "agreed_to_tos": "on",
                "next": "https://example.com/",
            },
        )
        self.assertTrue(
            User.objects.filter(email="test@example.com").exists(),
            msg="Expected user to be created",
        )
        user = User.objects.get(email="test@example.com")
        # Redirected to verification required page
        self.assertRedirects(
            response,
            get_email_verification_required_url(user),
        )

    def test_duplicate_email_unverified(self):
        """Signup using an exiting email should look like a successful signup."""
        response = self.client.post(
            self.signup_url,
            {
                # Different case, still considered duplicate
                "email": "USER@EXAMPLE.COM",
                "password1": "P@ssw0rd!",
                "password2": "P@ssw0rd!",
                "agreed_to_tos": "on",
            },
            follow=True,
        )
        # Redirected to verification required page
        self.assertRedirects(
            response,
            get_email_verification_required_url(self.test_user),
        )
        # Verification required page
        self.assertInHTML(
            "You need to verify your email address before you can log in.",
            response.content.decode("utf-8"),
        )

    def test_duplicate_email_verified(self):
        """Verified users should get a reminder mail."""
        self.test_user.email_verified = timezone.now()
        self.test_user.save()
        response = self.client.post(
            self.signup_url,
            {
                # Different case, still considered duplicate
                "email": "USER@EXAMPLE.COM",
                "password1": "P@ssw0rd!",
                "password2": "P@ssw0rd!",
                "agreed_to_tos": "on",
            },
            follow=True,
        )
        # Redirected to verification required page
        self.assertRedirects(
            response,
            get_email_verification_required_url(self.test_user),
        )
        # Verification required page
        self.assertInHTML(
            "You need to verify your email address before you can log in.",
            response.content.decode("utf-8"),
        )
        # Sends an email notification to the user
        self.assertEqual(len(mail.outbox), 1)
        message = mail.outbox[0]
        self.assertEqual(message.to, [self.test_user.email])
        self.assertEqual("Sign up request", message.subject)

    def test_with_logged_in_user(self):
        """A logged-in user should not be able to sign up again."""
        self.client.force_login(self.test_user)
        response = self.client.post(
            self.signup_url,
            {
                "email": "test@example.com",
                "password1": "P@ssw0rd!",
                "password2": "P@ssw0rd!",
                "agreed_to_tos": "on",
            },
        )
        self.assertEqual(response.status_code, HTTPStatus.FORBIDDEN)
