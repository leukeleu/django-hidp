from http import HTTPStatus

from django.test import TestCase
from django.urls import reverse

from hidp.accounts.forms import EditUserForm
from hidp.test.factories import user_factories


class TestManageAccountView(TestCase):
    @classmethod
    def setUpTestData(cls):
        cls.user = user_factories.UserFactory()
        cls.manage_account_url = reverse("hidp_accounts:manage_account")

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
        cls.edit_account_url = reverse("hidp_accounts:edit_account")

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
        self.assertInHTML(
            "Account updated successfully."
            '<a href="/manage/edit-account/" aria-label="Dismiss">✕</a>',
            response.content.decode("utf-8"),
        )
