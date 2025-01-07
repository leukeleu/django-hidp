import io

from http import HTTPStatus
from unittest import mock

from django.contrib import auth
from django.core import mail
from django.core.management import call_command
from django.test import TestCase
from django.urls import reverse
from django.utils import timezone

from hidp.accounts import tokens
from hidp.accounts.email_verification import remove_stale_unverified_accounts
from hidp.accounts.forms import EmailVerificationForm
from hidp.test.factories import user_factories

UserModel = auth.get_user_model()


class TestEmailVerificationRequiredView(TestCase):
    @classmethod
    def setUpTestData(cls):
        cls.user = user_factories.UserFactory()
        cls.url = reverse(
            "hidp_accounts:email_verification_required",
            kwargs={
                "token": tokens.email_verification_request_token_generator.make_token(
                    cls.user
                )
            },
        )

    def _assert_response(self, response, *, validlink=True):
        """Convenience method to assert the response."""
        self.assertEqual(response.status_code, HTTPStatus.OK)
        if validlink:
            self.assertTemplateUsed(
                response, "hidp/accounts/verification/email_verification_required.html"
            )
        else:
            self.assertTemplateUsed(
                response,
                "hidp/accounts/verification/email_verification_required_invalid_link.html",
            )

    def test_valid_get(self):
        """Works when the token is considered valid."""
        self._assert_response(self.client.get(self.url, follow=True))

    def test_get_invalid_token(self):
        """Invalid token."""
        response = self.client.get(
            reverse(
                "hidp_accounts:email_verification_required",
                kwargs={"token": "invalid-value:invalid-signature"},
            ),
            follow=True,
        )
        self._assert_response(response, validlink=False)

    def test_no_token_in_session(self):
        """Placeholder token, no token in session."""
        response = self.client.get(
            reverse(
                "hidp_accounts:email_verification_required",
                kwargs={"token": "email"},
            ),
            follow=True,
        )
        self._assert_response(response, validlink=False)

    def test_post(self):
        """Send the verification email."""
        # Get the page first, to populate the session
        response = self.client.get(self.url, follow=True)
        # Post to the redirected URL
        with (
            self.assertTemplateUsed("hidp/accounts/verification/email/verification_subject.txt"),
            self.assertTemplateUsed("hidp/accounts/verification/email/verification_body.txt"),
            self.assertTemplateUsed("hidp/accounts/verification/email/verification_body.html"),
        ):  # fmt: skip
            self.client.post(response.redirect_chain[-1][0], follow=True)
        # Verification email sent
        self.assertEqual(len(mail.outbox), 1)
        message = mail.outbox[0]
        self.assertEqual(
            message.subject,
            "Verify your email address",
        )

    def test_post_invalid_token(self):
        """Does not send the verification email when the token is invalid."""
        # Get the page first, to populate the session
        response = self.client.get(
            reverse(
                "hidp_accounts:email_verification_required",
                kwargs={"token": "invalid-value:invalid-signature"},
            ),
            follow=True,
        )
        # Post to the redirected URL
        self.client.post(response.redirect_chain[-1][0], follow=True)
        # Verification email not sent
        self.assertEqual(len(mail.outbox), 0)
        self._assert_response(response, validlink=False)


class TestEmailVerificationView(TestCase):
    @classmethod
    def setUpTestData(cls):
        cls.user = user_factories.UserFactory()
        cls.url = reverse(
            "hidp_accounts:verify_email",
            kwargs={
                "token": tokens.email_verification_token_generator.make_token(cls.user)
            },
        )

    def _assert_response(self, response, *, validlink=True):
        """Convenience method to assert the response."""
        self.assertEqual(response.status_code, HTTPStatus.OK)
        if validlink:
            self.assertTemplateUsed(
                response, "hidp/accounts/verification/verify_email.html"
            )
        else:
            self.assertTemplateUsed(
                response, "hidp/accounts/verification/verify_email_invalid_link.html"
            )

    def test_valid_get(self):
        """Works when the token is considered valid."""
        self._assert_response(self.client.get(self.url, follow=True))

    def test_get_invalid_token(self):
        """Invalid token."""
        response = self.client.get(
            reverse(
                "hidp_accounts:verify_email",
                kwargs={"token": "invalid-value:invalid-signature"},
            ),
            follow=True,
        )
        self._assert_response(response, validlink=False)

    def test_no_token_in_session(self):
        """Placeholder token, no token in session."""
        response = self.client.get(
            reverse(
                "hidp_accounts:verify_email",
                kwargs={"token": "email"},
            ),
            follow=True,
        )
        self._assert_response(response, validlink=False)

    def test_inactive_user(self):
        """Inactive user."""
        self.user.is_active = False
        self.user.save()
        response = self.client.get(self.url, follow=True)
        self._assert_response(response, validlink=False)

    def test_already_verified_user(self):
        """Already verified user."""
        self.user.email_verified = timezone.now()
        self.user.save()
        response = self.client.get(self.url, follow=True)
        self._assert_response(response, validlink=False)

    def test_post(self):
        """Update the user's email_verified field."""
        # Get the page first, to populate the session
        response = self.client.get(self.url, follow=True)
        # Post to the redirected URL
        response = self.client.post(response.redirect_chain[-1][0], follow=True)
        self.user.refresh_from_db()
        self.assertIsNotNone(
            self.user.email_verified, msg="Expected email to be verified."
        )
        self.assertAlmostEqual(
            self.user.email_verified,
            timezone.now(),
            delta=timezone.timedelta(seconds=5),
        )
        self.assertURLEqual(
            response.redirect_chain[-1][0],
            reverse("hidp_accounts:email_verification_complete"),
        )

    def test_post_invalid_token(self):
        # Get the page first, to populate the session
        response = self.client.get(
            reverse(
                "hidp_accounts:verify_email",
                kwargs={"token": "invalid-value:invalid-signature"},
            ),
            follow=True,
        )
        # Post to the redirected URL
        self.client.post(response.redirect_chain[-1][0], follow=True)
        # User's email_verified field not updated
        self.user.refresh_from_db()
        self.assertIsNone(
            self.user.email_verified, msg="Expected email to not be verified."
        )
        self._assert_response(response, validlink=False)


class TestEmailVerificationForm(TestCase):
    def test_form_for_user_no_name(self):
        user = user_factories.UserFactory(first_name="", last_name="")
        form = EmailVerificationForm(instance=user)
        self.assertEqual(form.initial["first_name"], "")
        self.assertEqual(form.initial["last_name"], "")
        self.assertTrue(form.fields["first_name"].required)
        self.assertTrue(form.fields["last_name"].required)

    def test_form_for_user_with_partial_name(self):
        user = user_factories.UserFactory(first_name="", last_name="White")
        form = EmailVerificationForm(instance=user)
        self.assertEqual(form.initial["first_name"], "")
        self.assertEqual(form.initial["last_name"], "White")
        self.assertTrue(form.fields["first_name"].required)
        self.assertTrue(form.fields["last_name"].required)

    def test_form_for_user_with_name(self):
        """
        Form should not have first and last name fields.

        The user has probably been created using an OIDC connection, and the given name
        and family name were provided by the OIDC provider.
        """
        user = user_factories.UserFactory(first_name="Walter", last_name="White")
        form = EmailVerificationForm(instance=user)
        self.assertNotIn("first_name", form.fields)
        self.assertNotIn("last_name", form.fields)

    def test_updates_name_fields(self):
        user = user_factories.UserFactory(first_name="", last_name="")
        form = EmailVerificationForm(
            instance=user,
            data={
                "first_name": "Walter",
                "last_name": "White",
            },
        )
        self.assertTrue(form.is_valid())
        form.save()
        user.refresh_from_db()
        self.assertEqual(user.first_name, "Walter")
        self.assertEqual(user.last_name, "White")


class TestRemoveUnverifiedAccounts(TestCase):
    @classmethod
    def setUpTestData(cls):
        cls.stale_user = user_factories.UserFactory(
            email_verified=None,
            date_joined=timezone.now() - timezone.timedelta(days=91),
        )
        cls.unverified_user = user_factories.UserFactory(
            date_joined=timezone.now() - timezone.timedelta(days=31)
        )
        cls.verified_user = user_factories.VerifiedUserFactory()

    def test_remove_stale_unverified_accounts_dry_run(self):
        removed_accounts = remove_stale_unverified_accounts(dry_run=True)
        users_exist = (
            UserModel.objects.filter(pk=user.pk).exists()
            for user in (self.stale_user, self.unverified_user, self.verified_user)
        )
        self.assertEqual(
            removed_accounts,
            1,
            msg="Expected 1 account to be selected for removal.",
        )
        self.assertTrue(
            all(users_exist),
            msg="Expected all users to still exist after dry run.",
        )

    def test_remove_stale_unverified_accounts(self):
        removed_accounts = remove_stale_unverified_accounts()
        self.assertEqual(
            removed_accounts,
            1,
            msg="Expected 1 account to be selected for removal.",
        )
        self.assertFalse(
            UserModel.objects.filter(pk=self.stale_user.pk).exists(),
            msg="Expected stale user to be removed, joined more than 90 days ago.",
        )
        users_exist = (
            UserModel.objects.filter(pk=user.pk).exists()
            for user in (self.unverified_user, self.verified_user)
        )
        self.assertTrue(
            all(users_exist),
            msg="Expected non-stale users to still exist.",
        )

    def test_remove_stale_unverified_accounts_30_days(self):
        removed_accounts = remove_stale_unverified_accounts(days=30)
        self.assertEqual(removed_accounts, 2)
        self.assertFalse(
            UserModel.objects.filter(pk=self.stale_user.pk).exists(),
            msg="Expected user to be removed, joined more than 30 days ago.",
        )
        self.assertFalse(
            UserModel.objects.filter(pk=self.unverified_user.pk).exists(),
            msg="Expected user to be removed, joined more than 30 days ago.",
        )
        self.assertTrue(
            UserModel.objects.filter(pk=self.verified_user.pk).exists(),
            msg="Expected user to still exist, user is verified.",
        )

    @mock.patch(
        "hidp.accounts.management.commands.remove_stale_unverified_accounts.remove_stale_unverified_accounts",
        return_value=1,
    )
    def test_remove_stale_unverified_accounts_management_command_dry_run(
        self, mock_remove_stale_unverified_accounts
    ):
        stdout = io.StringIO()

        call_command("remove_stale_unverified_accounts", dry_run=True, stdout=stdout)
        self.assertIn(
            "Removing accounts that have not been verified within 90 days...",
            stdout.getvalue(),
        )
        self.assertIn("1 unverified account(s) would be removed.", stdout.getvalue())
        mock_remove_stale_unverified_accounts.assert_called_once_with(
            days=90, dry_run=True
        )

    @mock.patch(
        "hidp.accounts.management.commands.remove_stale_unverified_accounts.remove_stale_unverified_accounts",
        return_value=1,
    )
    def test_remove_stale_unverified_accounts_management_command(
        self, mock_remove_stale_unverified_accounts
    ):
        stdout = io.StringIO()

        call_command("remove_stale_unverified_accounts", stdout=stdout)
        self.assertIn(
            "Removing accounts that have not been verified within 90 days...",
            stdout.getvalue(),
        )
        self.assertIn(
            "Successfully removed 1 unverified account(s).", stdout.getvalue()
        )
        mock_remove_stale_unverified_accounts.assert_called_once_with(
            days=90, dry_run=False
        )

    @mock.patch(
        "hidp.accounts.management.commands.remove_stale_unverified_accounts.remove_stale_unverified_accounts",
        return_value=2,
    )
    def test_remove_stale_unverified_accounts_management_command_30_days(
        self, mock_remove_stale_unverified_accounts
    ):
        stdout = io.StringIO()

        call_command("remove_stale_unverified_accounts", days=30, stdout=stdout)
        self.assertIn(
            "Successfully removed 2 unverified account(s).", stdout.getvalue()
        )
        mock_remove_stale_unverified_accounts.assert_called_once_with(
            days=30, dry_run=False
        )
