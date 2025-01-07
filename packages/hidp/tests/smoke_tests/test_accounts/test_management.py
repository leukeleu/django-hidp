from datetime import timedelta
from http import HTTPStatus

from django.core import mail
from django.test import TestCase
from django.urls import reverse
from django.utils import timezone

from hidp.accounts.forms import EditUserForm
from hidp.test.factories import user_factories


class TestManageAccountView(TestCase):
    @classmethod
    def setUpTestData(cls):
        cls.user = user_factories.UserFactory()
        cls.manage_account_url = reverse("hidp_account_management:manage_account")

    def test_login_required(self):
        """Anonymous users should be redirected to the login page."""
        response = self.client.get(self.manage_account_url)
        self.assertRedirects(
            response,
            f"{reverse('hidp_accounts:login')}?next={self.manage_account_url}",
        )

    def test_get(self):
        """The manage account page should be displayed for authenticated users."""
        self.client.force_login(self.user)
        response = self.client.get(self.manage_account_url)
        self.assertEqual(response.status_code, HTTPStatus.OK)
        self.assertTemplateUsed(
            response, "hidp/accounts/management/manage_account.html"
        )


class TestEditAccountView(TestCase):
    @classmethod
    def setUpTestData(cls):
        cls.user = user_factories.UserFactory()
        cls.edit_account_url = reverse("hidp_account_management:edit_account")

    def test_login_required(self):
        """Anonymous users should be redirected to the login page."""
        response = self.client.get(self.edit_account_url)
        self.assertRedirects(
            response,
            f"{reverse('hidp_accounts:login')}?next={self.edit_account_url}",
        )

    def test_get(self):
        """The edit user page should be displayed for authenticated users."""
        self.client.force_login(self.user)
        response = self.client.get(self.edit_account_url)
        self.assertEqual(response.status_code, HTTPStatus.OK)
        self.assertTemplateUsed(response, "hidp/accounts/management/edit_account.html")
        self.assertIn("form", response.context)
        self.assertIsInstance(response.context["form"], EditUserForm)

        form = response.context["form"]
        self.assertEqual(form.initial["first_name"], self.user.first_name)
        self.assertEqual(form.initial["last_name"], self.user.last_name)

    def test_edit_account(self):
        """The user's information should be updated."""
        self.client.force_login(self.user)
        response = self.client.post(
            self.edit_account_url,
            {
                "first_name": "New",
                "last_name": "Name",
            },
            follow=True,
        )

        # User's information should be updated
        self.user.refresh_from_db()
        self.assertEqual(self.user.first_name, "New")
        self.assertEqual(self.user.last_name, "Name")

        # Success message should be displayed
        self.assertRedirects(
            response, reverse("hidp_account_management:edit_account_done")
        )
        self.assertTemplateUsed(
            response, "hidp/accounts/management/edit_account_done.html"
        )


class TestPasswordChangeView(TestCase):
    @classmethod
    def setUpTestData(cls):
        cls.user = user_factories.UserFactory()
        cls.change_password_url = reverse("hidp_account_management:change_password")

    def test_login_required(self):
        """Anonymous users should be redirected to the login page."""
        self.client.logout()
        response = self.client.get(self.change_password_url)
        self.assertRedirects(
            response,
            f"{reverse('hidp_accounts:login')}?next={self.change_password_url}",
        )

    def test_redirect_user_without_usable_password(self):
        """Users without a usable password should be redirected to the manage page."""
        self.user.set_unusable_password()
        self.user.save()
        self.client.force_login(self.user)
        response = self.client.get(self.change_password_url, follow=True)
        self.assertRedirects(response, reverse("hidp_account_management:set_password"))

    def test_get(self):
        """The password change page should be displayed for authenticated users."""
        self.client.force_login(self.user)
        response = self.client.get(self.change_password_url)
        self.assertEqual(response.status_code, HTTPStatus.OK)
        self.assertTemplateUsed(
            response, "hidp/accounts/management/password_change.html"
        )
        self.assertIn("form", response.context)
        self.assertTrue(response.context["form"].fields["old_password"].required)

    def test_change_password(self):
        """The user's password should be updated."""
        self.client.force_login(self.user)
        with (
            self.assertTemplateUsed("hidp/accounts/management/email/password_changed_subject.txt"),
            self.assertTemplateUsed("hidp/accounts/management/email/password_changed_body.txt"),
            self.assertTemplateUsed("hidp/accounts/management/email/password_changed_body.html"),
        ):  # fmt: skip
            response = self.client.post(
                self.change_password_url,
                {
                    "old_password": "P@ssw0rd!",
                    "new_password1": "new_password",
                    "new_password2": "new_password",
                },
                follow=True,
            )

        # User's password should be updated
        self.user.refresh_from_db()
        self.assertTrue(self.user.check_password("new_password"))

        # Redirect to the success page
        self.assertRedirects(
            response, reverse("hidp_account_management:change_password_done")
        )
        self.assertTemplateUsed("hidp/accounts/management/password_change_done.html")

        # Changed password mail should be sent
        self.assertEqual(1, len(mail.outbox))
        message = mail.outbox[0]
        self.assertEqual(message.to, [self.user.email])
        self.assertEqual("Your password has been changed", message.subject)
        self.assertIn(
            reverse("hidp_accounts:password_reset_request"),
            message.body,
        )


class TestSetPasswordView(TestCase):
    @classmethod
    def setUpTestData(cls):
        cls.user = user_factories.UserFactory()
        cls.user.set_unusable_password()
        cls.user.save()
        cls.set_password_url = reverse("hidp_account_management:set_password")

    def test_login_required(self):
        """Anonymous users should be redirected to the login page."""
        response = self.client.get(self.set_password_url)
        self.assertRedirects(
            response,
            f"{reverse('hidp_accounts:login')}?next={self.set_password_url}",
        )

    def test_redirect_user_with_usable_password(self):
        """Users without a usable password should be redirected to the manage page."""
        self.user.set_password("P@ssw0rd!")
        self.user.save()
        self.client.force_login(self.user)
        response = self.client.get(self.set_password_url, follow=True)
        self.assertRedirects(
            response, reverse("hidp_account_management:change_password")
        )

    def test_get_not_recently_authenticated(self):
        """The must reauthenticate flag should be set to True."""
        self.client.force_login(self.user)
        self.user.last_login = timezone.now() - timedelta(days=1)
        self.user.save()
        response = self.client.get(self.set_password_url)
        self.assertEqual(response.status_code, HTTPStatus.OK)
        self.assertTemplateUsed(response, "hidp/accounts/management/set_password.html")
        self.assertTrue(
            response.context["must_reauthenticate"],
            msg="Expected must_reauthenticate to be True.",
        )

    def test_post_not_recently_authenticated(self):
        """User is redirected to the same page to reauthenticate."""
        self.client.force_login(self.user)
        self.user.last_login = timezone.now() - timedelta(days=1)
        self.user.save()
        response = self.client.post(
            self.set_password_url,
            {
                "new_password1": "new_password",
                "new_password2": "new_password",
            },
            follow=True,
        )

        # User's password should not be updated
        self.user.refresh_from_db()
        self.assertFalse(
            self.user.check_password("new_password"),
            msg="Expected password to not be set.",
        )

        # Redirect to the same page
        self.assertRedirects(response, self.set_password_url)

    def test_get(self):
        """The set password page should be displayed for authenticated users."""
        self.client.force_login(self.user)
        response = self.client.get(self.set_password_url)
        self.assertEqual(response.status_code, HTTPStatus.OK)
        self.assertTemplateUsed(response, "hidp/accounts/management/set_password.html")
        self.assertIn("form", response.context)

    def test_set_password(self):
        """The user's password should be set."""
        self.client.force_login(self.user)
        with (
            self.assertTemplateUsed("hidp/accounts/management/email/password_changed_subject.txt"),
            self.assertTemplateUsed("hidp/accounts/management/email/password_changed_body.txt"),
            self.assertTemplateUsed("hidp/accounts/management/email/password_changed_body.html"),
        ):  # fmt: skip
            response = self.client.post(
                self.set_password_url,
                {
                    "new_password1": "new_password",
                    "new_password2": "new_password",
                },
                follow=True,
            )

        # User's password should be updated
        self.user.refresh_from_db()
        self.assertTrue(
            self.user.check_password("new_password"), msg="Expected password to be set."
        )

        # Redirect to the success page
        self.assertRedirects(
            response, reverse("hidp_account_management:set_password_done")
        )
        self.assertTemplateUsed("hidp/accounts/management/set_change_done.html")

        # Changed password mail should be sent
        self.assertEqual(1, len(mail.outbox))
        message = mail.outbox[0]
        self.assertEqual(message.to, [self.user.email])
        self.assertEqual("Your password has been changed", message.subject)
        self.assertIn(
            reverse("hidp_accounts:password_reset_request"),
            message.body,
        )
