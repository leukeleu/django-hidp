import io

from unittest import mock

from django.contrib import auth
from django.core.management import call_command
from django.test import TestCase
from django.utils import timezone

from hidp.accounts.email_verification import remove_stale_unverified_accounts
from hidp.test.factories import user_factories

UserModel = auth.get_user_model()


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
