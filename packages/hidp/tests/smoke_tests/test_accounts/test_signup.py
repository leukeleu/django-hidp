from http import HTTPStatus
from unittest import mock

from django.contrib.auth import get_user_model
from django.core import mail
from django.test import TransactionTestCase, override_settings
from django.urls import reverse
from django.utils import timezone

from hidp.accounts.forms import UserCreationForm
from hidp.test.factories import user_factories

User = get_user_model()


@override_settings(LANGUAGE_CODE="en", REGISTRATION_ENABLED=True)
class TestRegistrationView(TransactionTestCase):
    def setUp(self):
        self.test_user = user_factories.UserFactory(email="user@example.com")
        self.signup_url = reverse("hidp_accounts:register")

    def test_get(self):
        """The registration form should be displayed."""
        response = self.client.get(self.signup_url)
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "hidp/accounts/register.html")
        self.assertIn("form", response.context)
        self.assertIsInstance(response.context["form"], UserCreationForm)

    def test_get_tos(self):
        """The terms of service should be displayed."""
        response = self.client.get(reverse("hidp_accounts:tos"))
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "hidp/accounts/tos.html")

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
        with (
            self.assertTemplateUsed("hidp/accounts/verification/email/verification_subject.txt"),
            self.assertTemplateUsed("hidp/accounts/verification/email/verification_body.txt"),
            self.assertTemplateUsed("hidp/accounts/verification/email/verification_body.html"),
        ):  # fmt: skip
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
            reverse(
                "hidp_accounts:email_verification_required", kwargs={"token": "email"}
            ),
        )
        # Verification required page
        self.assertInHTML(
            "Verification required",
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
            follow=True,
        )
        self.assertTrue(
            User.objects.filter(email="test@example.com").exists(),
            msg="Expected user to be created",
        )
        # Redirected to verification required page
        self.assertRedirects(
            response,
            reverse(
                "hidp_accounts:email_verification_required", kwargs={"token": "email"}
            )
            + "?next=/example/",
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
            follow=True,
        )
        self.assertTrue(
            User.objects.filter(email="test@example.com").exists(),
            msg="Expected user to be created",
        )
        # Redirected to verification required page
        self.assertRedirects(
            response,
            reverse(
                "hidp_accounts:email_verification_required", kwargs={"token": "email"}
            ),
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
            reverse(
                "hidp_accounts:email_verification_required", kwargs={"token": "email"}
            ),
        )
        # Verification required page
        self.assertInHTML(
            "Verification required",
            response.content.decode("utf-8"),
        )

    def test_duplicate_email_verified(self):
        """Verified users should get a reminder mail."""
        self.test_user.email_verified = timezone.now()
        self.test_user.save()
        with (
            self.assertTemplateUsed("hidp/accounts/verification/email/account_exists_subject.txt"),
            self.assertTemplateUsed("hidp/accounts/verification/email/account_exists_body.txt"),
            self.assertTemplateUsed("hidp/accounts/verification/email/account_exists_body.html"),
        ):  # fmt: skip
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
            reverse(
                "hidp_accounts:email_verification_required", kwargs={"token": "email"}
            ),
        )
        # Verification required page
        self.assertInHTML(
            "Verification required",
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

    def test_account_exists(self):
        """Existing users should be notified if someone tries to use their email."""
        existing_user = user_factories.VerifiedUserFactory()
        with (
            self.assertTemplateUsed("hidp/accounts/verification/email/account_exists_subject.txt"),
            self.assertTemplateUsed("hidp/accounts/verification/email/account_exists_body.txt"),
            self.assertTemplateUsed("hidp/accounts/verification/email/account_exists_body.html"),
        ):  # fmt: skip
            response = self.client.post(
                self.signup_url,
                {
                    "email": existing_user.email,
                    "password1": "P@ssw0rd!",
                    "password2": "P@ssw0rd!",
                    "agreed_to_tos": "on",
                },
                follow=True,
            )

        # Pretend the registration was successful
        self.assertRedirects(
            response,
            reverse(
                "hidp_accounts:email_verification_required",
                kwargs={"token": "email"},
            ),
        )

        # Account exists email sent
        self.assertEqual(len(mail.outbox), 1)
        message = mail.outbox[0]
        self.assertEqual(
            message.subject,
            "Sign up request",
        )
        self.assertIn(
            "You're receiving this email because you attempted to create an"
            " account using this email address."
            " However, an account already exists with this email address.",
            message.body,
        )

    def test_inactive_account_exists(self):
        """Inactive users should not be notified if someone tries to use their email."""
        inactive_user = user_factories.VerifiedUserFactory(is_active=False)
        response = self.client.post(
            self.signup_url,
            {
                "email": inactive_user.email,
                "password1": "P@ssw0rd!",
                "password2": "P@ssw0rd!",
                "agreed_to_tos": "on",
            },
            follow=True,
        )

        # Pretend the registration was successful
        self.assertRedirects(
            response,
            reverse(
                "hidp_accounts:email_verification_required",
                kwargs={"token": "email"},
            ),
        )

        # Account exists email not sent
        self.assertEqual(len(mail.outbox), 0)

    @mock.patch(
        "hidp.accounts.views.mailers.EmailVerificationMailer.send",
        side_effect=Exception,
    )
    def test_verification_email_error(self, mock_send):
        """Errors are logged when sending the verification email."""
        # This is a fix for Django's CVE-2024-45231. The email backend
        # might raise an exception when sending an email, which could
        # be used to enumerate valid email addresses.
        with self.assertLogs("hidp.accounts.views", level="ERROR") as cm:
            self.client.post(
                self.signup_url,
                {
                    "email": "test@example.com",
                    "password1": "P@ssw0rd!",
                    "password2": "P@ssw0rd!",
                    "agreed_to_tos": "on",
                },
            )
        self.assertIn("Failed to send verification email.", cm.records[0].msg)
        self.assertEqual(0, len(mail.outbox))

    @mock.patch(
        "hidp.accounts.views.mailers.AccountExistsMailer.send",
        side_effect=Exception,
    )
    def test_account_exists_email_error(self, mock_send):
        """Errors are logged when sending the account exists email."""
        # This is a fix for Django's CVE-2024-45231. The email backend
        # might raise an exception when sending an email, which could
        # be used to enumerate valid email addresses.
        user_factories.VerifiedUserFactory(email="test@example.com")
        with self.assertLogs("hidp.accounts.views", level="ERROR") as cm:
            self.client.post(
                self.signup_url,
                {
                    "email": "test@example.com",
                    "password1": "P@ssw0rd!",
                    "password2": "P@ssw0rd!",
                    "agreed_to_tos": "on",
                },
            )
        self.assertIn("Failed to send verification email.", cm.records[0].msg)
        self.assertEqual(0, len(mail.outbox))


@override_settings(REGISTRATION_ENABLED=False)
class TestRegistrationViewNotEnabled(TransactionTestCase):
    def setUp(self):
        self.signup_url = reverse("hidp_accounts:register")

    def test_get_signup_disabled(self):
        """The view should turn a 404 when registration is disabled."""
        response = self.client.get(self.signup_url)
        self.assertEqual(response.status_code, HTTPStatus.NOT_FOUND)

    def test_post_signup_disabled(self):
        """The view should not process POST requests when registration is disabled."""
        response = self.client.post(
            self.signup_url,
            {
                "email": "test@example.com",
                "password1": "P@ssw0rd!",
                "password2": "P@ssw0rd!",
                "agreed_to_tos": "on",
            },
        )
        self.assertEqual(response.status_code, HTTPStatus.NOT_FOUND)
