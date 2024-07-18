from http import HTTPStatus

from django.core import mail
from django.test import TestCase
from django.urls import reverse

from hidp.accounts import forms
from hidp.test.factories import user_factories


class TestPasswordResetFlow(TestCase):
    @classmethod
    def setUpTestData(cls):
        cls.user = user_factories.UserFactory()

    def test_get_password_reset_request(self):
        """Render the password reset request form."""
        response = self.client.get(reverse("hidp_accounts:password_reset_request"))
        self.assertTemplateUsed(
            response, "accounts/recovery/password_reset_request.html"
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
        """A user without a password cannot request a password reset email."""
        self.user.set_unusable_password()
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

    def test_user_request_password_reset_email(self):
        """A user can request a password reset email."""
        with (
            self.assertTemplateUsed("accounts/recovery/email/password_reset_subject.txt"),
            self.assertTemplateUsed("accounts/recovery/email/password_reset_body.txt"),
        ):  # fmt: skip
            response = self.client.post(
                reverse("hidp_accounts:password_reset_request"),
                {"email": self.user.email},
                follow=True,
            )
        self.assertEqual(1, len(mail.outbox))
        message = mail.outbox[0]
        self.assertEqual(message.to, [self.user.email])
        self.assertEqual(message.subject, "Password reset request")
        self.assertIn(
            forms.PasswordResetRequestForm().get_password_reset_url(
                user=self.user,
                base_url="http://testserver",
                password_reset_view="hidp_accounts:password_reset",
            ),
            message.body,
        )
        self.assertRedirects(
            response,
            reverse("hidp_accounts:password_reset_email_sent"),
        )
        self.assertTemplateUsed(
            response,
            "accounts/recovery/password_reset_email_sent.html",
        )

    def test_get_password_reset_url(self):
        """Render the password reset form."""
        password_reset_url = forms.PasswordResetRequestForm().get_password_reset_url(
            user=self.user,
            base_url="https://testserver",
            password_reset_view="hidp_accounts:password_reset",
        )
        response = self.client.get(password_reset_url, follow=True)
        self.assertEqual(response.status_code, HTTPStatus.OK)
        self.assertTemplateUsed(response, "accounts/recovery/password_reset.html")
        self.assertIn("validlink", response.context)
        self.assertTrue(
            response.context["validlink"], msg="Expected the link to be valid."
        )
        self.assertIsInstance(response.context["form"], forms.PasswordResetForm)

    def test_post_password_reset_url(self):
        """Reset the user's password."""
        password_reset_url = forms.PasswordResetRequestForm().get_password_reset_url(
            user=self.user,
            base_url="https://testserver",
            password_reset_view="hidp_accounts:password_reset",
        )
        # Need to get the password reset form first to populate a session value.
        response = self.client.get(
            password_reset_url,
            follow=True,
        )
        self.assertEqual(response.status_code, HTTPStatus.OK)
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
            "accounts/recovery/password_reset_complete.html",
        )

        with self.subTest("The password reset URL is invalid after use."):
            response = self.client.get(password_reset_url, follow=True)
            self.assertIn("validlink", response.context)
            self.assertFalse(
                response.context["validlink"], msg="Expected the link to be invalid."
            )
