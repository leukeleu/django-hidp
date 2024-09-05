from http import HTTPStatus

from django.test import TestCase
from django.urls import reverse

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
