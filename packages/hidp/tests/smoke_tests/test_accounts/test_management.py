from http import HTTPStatus

from django.test import TestCase
from django.urls import reverse

from hidp.accounts.forms import EditUserForm
from hidp.config.oidc_clients import configure_oidc_clients
from hidp.federated.models import OpenIdConnection
from hidp.test.factories import user_factories
from tests.unit_tests.test_federated.test_providers.example import ExampleOIDCClient


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


class TestOIDCLinkedServicesView(TestCase):
    @classmethod
    def setUpTestData(cls):
        cls.user = user_factories.UserFactory()
        cls.oidc_linked_services_url = reverse("hidp_accounts:oidc_linked_services")

    def setUp(self):
        configure_oidc_clients(ExampleOIDCClient(client_id="test"))

    def test_login_required(self):
        """Anonymous users should be redirected to the login page."""
        response = self.client.get(self.oidc_linked_services_url)
        self.assertRedirects(
            response,
            f"{reverse('hidp_accounts:login')}?next={self.oidc_linked_services_url}",
        )

    def test_available_services(self):
        self.client.force_login(self.user)
        response = self.client.get(self.oidc_linked_services_url)

        self.assertInHTML(
            "Available services",
            response.content.decode("utf-8"),
        )
        self.assertContains(
            response,
            '<form action="/login/oidc/authenticate/example/" method="POST">',
        )
        self.assertInHTML(
            "<button type='submit'>Link with Example</button>",
            response.content.decode("utf-8"),
        )

    def test_linked_services(self):
        OpenIdConnection.objects.create(
            user=self.user,
            provider_key="example",
            issuer_claim="example",
            subject_claim="test-subject",
        )

        self.client.force_login(self.user)
        response = self.client.get(self.oidc_linked_services_url)

        self.assertInHTML(
            "Linked services",
            response.content.decode("utf-8"),
        )
        self.assertInHTML(
            "Linked with Example",
            response.content.decode("utf-8"),
        )


class TestPasswordChangeView(TestCase):
    @classmethod
    def setUpTestData(cls):
        cls.user = user_factories.UserFactory()
        cls.change_password_url = reverse("hidp_accounts:change_password")

    def test_login_required(self):
        """Anonymous users should be redirected to the login page."""
        self.client.logout()
        response = self.client.get(self.change_password_url)
        self.assertRedirects(
            response,
            f"{reverse('hidp_accounts:login')}?next={self.change_password_url}",
        )

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

