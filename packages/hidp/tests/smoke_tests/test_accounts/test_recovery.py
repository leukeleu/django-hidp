from http import HTTPStatus
from unittest import mock

from django.core import mail
from django.test import TestCase
from django.urls import reverse

from hidp.accounts import forms, mailers
from hidp.test.factories import user_factories


class TestPasswordResetFlow(TestCase):
    @classmethod
    def setUpTestData(cls):
        cls.user = user_factories.UserFactory()

    def test_get_password_reset_request(self):
        """Render the password reset request form."""
        response = self.client.get(reverse("hidp_accounts:password_reset_request"))
        self.assertTemplateUsed(
            response, "hidp/accounts/recovery/password_reset_request.html"
        )
        self.assertIsInstance(response.context["form"], forms.PasswordResetRequestForm)

    def test_non_user_request_password_reset_email(self):
        """A non-user cannot request a password reset email."""
        response = self.client.post(
            reverse("hidp_accounts:password_reset_request"),
            {"email": "not-a-user@example.com"},
        )
        self.assertEqual(0, len(mail.outbox))
        # Even though the email was not sent, the user is redirected to
        # the success page to prevent email enumeration attacks.
        self.assertRedirects(
            response,
            reverse("hidp_accounts:password_reset_email_sent"),
            fetch_redirect_response=True,
        )

    def test_inactive_user_request_password_reset_email(self):
        """An inactive user cannot request a password reset email."""
        self.user.is_active = False
        self.user.save()
        response = self.client.post(
            reverse("hidp_accounts:password_reset_request"),
            {"email": self.user.email},
        )
        self.assertEqual(0, len(mail.outbox))
        self.assertRedirects(
            response,
            reverse("hidp_accounts:password_reset_email_sent"),
            fetch_redirect_response=True,
        )

    def test_user_without_a_password_request_password_reset_email(self):
        self.user.set_unusable_password()
        self.user.save()
        """A user without a password receives the set password email."""
        with (
            self.assertTemplateUsed("hidp/accounts/recovery/email/set_password_subject.txt"),
            self.assertTemplateUsed("hidp/accounts/recovery/email/set_password_body.txt"),
            self.assertTemplateUsed("hidp/accounts/recovery/email/set_password_body.html")
        ):  # fmt: skip
            response = self.client.post(
                reverse("hidp_accounts:password_reset_request"),
                {"email": self.user.email},
                follow=True,
            )
        self.assertEqual(1, len(mail.outbox))
        message = mail.outbox[0]
        self.assertEqual(message.to, [self.user.email])
        self.assertEqual(message.subject, "Set a password")
        self.assertIn(
            reverse("hidp_account_management:set_password"),
            message.body,
        )
        self.assertRedirects(
            response,
            reverse("hidp_accounts:password_reset_email_sent"),
        )
        self.assertTemplateUsed(
            response,
            "hidp/accounts/recovery/password_reset_email_sent.html",
        )

    def test_user_request_password_reset_email(self):
        """A user can request a password reset email."""
        with (
            self.assertTemplateUsed("hidp/accounts/recovery/email/password_reset_subject.txt"),
            self.assertTemplateUsed("hidp/accounts/recovery/email/password_reset_body.txt"),
            self.assertTemplateUsed("hidp/accounts/recovery/email/password_reset_body.html"),
        ):  # fmt: skip
            response = self.client.post(
                reverse("hidp_accounts:password_reset_request"),
                {"email": self.user.email},
                follow=True,
            )
        self.assertEqual(1, len(mail.outbox))
        message = mail.outbox[0]
        self.assertEqual(message.to, [self.user.email])
        self.assertEqual(message.subject, "Reset your password")
        self.assertRegex(
            message.body,
            # Matches the password reset URL:
            # http://testserver/recover/password/MDE5MTkyY2UtODE0Yy03NjNlLTlhMGUtMmM1ODk3MGNkYTFj/cced4c-9a0766ea185039a6d293ff660c04007e/
            r"http://testserver/recover/password/[0-9A-Za-z]+/[0-9a-z]+-[0-9a-f]+/",
        )
        self.assertRedirects(
            response,
            reverse("hidp_accounts:password_reset_email_sent"),
        )
        self.assertTemplateUsed(
            response,
            "hidp/accounts/recovery/password_reset_email_sent.html",
        )

    @mock.patch(
        "hidp.accounts.views.mailers.PasswordResetRequestMailer.send",
        side_effect=Exception,
    )
    def test_password_reset_email_error(self, mock_send):
        """Errors are logged when sending the password reset email."""
        # This is a fix for Django's CVE-2024-45231. The email backend
        # might raise an exception when sending an email, which could
        # be used to enumerate valid email addresses.
        with self.assertLogs("hidp.accounts.views", level="ERROR") as cm:
            self.client.post(
                reverse("hidp_accounts:password_reset_request"),
                {"email": self.user.email},
            )
        self.assertIn("Failed to send password (re)set email.", cm.records[0].msg)
        self.assertEqual(0, len(mail.outbox))

    def test_get_password_reset_url(self):
        """Render the password reset form."""
        password_reset_url = mailers.PasswordResetRequestMailer(
            user=self.user,
            base_url="https://testserver",
        ).get_password_reset_url()
        response = self.client.get(password_reset_url, follow=True)
        self.assertEqual(response.status_code, HTTPStatus.OK)
        self.assertTemplateUsed(response, "hidp/accounts/recovery/password_reset.html")
        self.assertIsInstance(response.context["form"], forms.PasswordResetForm)

    def test_post_password_reset_url(self):
        """Reset the user's password."""
        password_reset_url = mailers.PasswordResetRequestMailer(
            user=self.user,
            base_url="https://testserver",
        ).get_password_reset_url()
        # Need to get the password reset form first to populate a session value.
        response = self.client.get(
            password_reset_url,
            follow=True,
        )
        self.assertEqual(response.status_code, HTTPStatus.OK)
        with (
            self.assertTemplateUsed("hidp/accounts/management/email/password_changed_subject.txt"),
            self.assertTemplateUsed("hidp/accounts/management/email/password_changed_body.txt"),
            self.assertTemplateUsed("hidp/accounts/management/email/password_changed_body.html"),
        ):  # fmt: skip
            response = self.client.post(
                # There is a redirect to remove the token from the URL.
                # The final destination is the URL we need to POST to.
                response.redirect_chain[-1][0],
                {
                    "new_password1": "newpassword",
                    "new_password2": "newpassword",
                },
                follow=True,
            )
        self.user.refresh_from_db()
        self.assertTrue(self.user.check_password("newpassword"))
        self.assertRedirects(
            response,
            reverse("hidp_accounts:password_reset_complete"),
        )
        self.assertTemplateUsed(
            response,
            "hidp/accounts/recovery/password_reset_complete.html",
        )

        # Changed password mail should be sent
        self.assertEqual(1, len(mail.outbox))
        message = mail.outbox[0]
        self.assertEqual(message.to, [self.user.email])
        self.assertEqual("Your password has been changed", message.subject)
        self.assertIn(
            reverse("hidp_accounts:password_reset_request"),
            message.body,
        )

        with self.subTest("The password reset URL is invalid after use."):
            response = self.client.get(password_reset_url, follow=True)
            self.assertTemplateUsed(
                response,
                "hidp/accounts/recovery/password_reset_invalid_link.html",
            )
