from datetime import timedelta
from http import HTTPStatus

from django.core import mail
from django.test import TestCase
from django.urls import reverse
from django.utils import timezone

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


class TestOIDCClient(ExampleOIDCClient):
    # Same as the ExampleOIDCClient, but with a different provider key.
    provider_key = "test"


class TestOIDCLinkedServicesView(TestCase):
    @classmethod
    def setUpTestData(cls):
        cls.user = user_factories.UserFactory()
        cls.user.set_unusable_password()
        cls.user.save()
        cls.oidc_linked_services_url = reverse("hidp_accounts:oidc_linked_services")

    def setUp(self):
        clients = [
            ExampleOIDCClient(client_id="example"),
            TestOIDCClient(client_id="test"),
        ]
        configure_oidc_clients(*clients)

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

        # No services linked
        self.assertNotInHTML("Linked services", response.content.decode("utf-8"))

        # List of available services should be displayed
        self.assertInHTML(
            "Available services",
            response.content.decode("utf-8"),
        )
        self.assertContains(
            response,
            '<form action="/login/oidc/authenticate/example/" method="POST">',
        )
        for name in ("Example", "Test"):
            self.assertInHTML(
                f"<button type='submit'>Link with {name}</button>",
                response.content.decode("utf-8"),
            )

    def test_linked_one_service(self):
        OpenIdConnection.objects.create(
            user=self.user,
            provider_key="example",
            issuer_claim="example",
            subject_claim="test-subject",
        )

        self.client.force_login(self.user)
        response = self.client.get(self.oidc_linked_services_url)

        # Unlinking is not possible with only one service linked and no password set
        self.assertFalse(
            response.context["can_unlink"], msg="Expected can_unlink to be False."
        )

        # The linked service should be displayed
        self.assertInHTML(
            "Linked services",
            response.content.decode("utf-8"),
        )
        self.assertInHTML("<li>Example</li>", response.content.decode("utf-8"))

        # Unlink button should not be available
        self.assertNotInHTML(
            '<a href="/login/oidc/unlink-account/example/"'
            ' aria-label="Unlink">Unlink</a>',
            response.content.decode("utf-8"),
        )

        # The remaining service should be available
        self.assertInHTML(
            "Available services",
            response.content.decode("utf-8"),
        )
        self.assertInHTML(
            "<button type='submit'>Link with Test</button>",
            response.content.decode("utf-8"),
        )

    def test_linked_all_services(self):
        OpenIdConnection.objects.create(
            user=self.user,
            provider_key="example",
            issuer_claim="example",
            subject_claim="test-subject",
        )
        OpenIdConnection.objects.create(
            user=self.user,
            provider_key="test",
            issuer_claim="example",
            subject_claim="test-subject",
        )

        self.client.force_login(self.user)
        response = self.client.get(self.oidc_linked_services_url)

        # Unlinking is possible with multiple services linked
        self.assertTrue(
            response.context["can_unlink"], msg="Expected can_unlink to be True."
        )

        self.assertInHTML(
            "Linked services",
            response.content.decode("utf-8"),
        )
        for key in ("example", "test"):
            self.assertInHTML(
                f"<li>{key.capitalize()}"
                f' <a href="/login/oidc/unlink-account/{key}/"'
                f' aria-label="Unlink">Unlink</a></li>',
                response.content.decode("utf-8"),
            )

        # No additional services should be available
        self.assertNotInHTML("Available services", response.content.decode("utf-8"))

    def test_linked_one_service_with_password_set(self):
        self.user.set_password("P@ssw0rd!")
        self.user.save()

        OpenIdConnection.objects.create(
            user=self.user,
            provider_key="example",
            issuer_claim="example",
            subject_claim="test-subject",
        )

        self.client.force_login(self.user)

        response = self.client.get(self.oidc_linked_services_url)

        # Unlinking is possible with one service linked and a password set
        self.assertTrue(
            response.context["can_unlink"], msg="Expected can_unlink to be True."
        )

        self.assertInHTML(
            "Linked services",
            response.content.decode("utf-8"),
        )
        self.assertInHTML(
            "<li>Example"
            ' <a href="/login/oidc/unlink-account/example/"'
            ' aria-label="Unlink">Unlink</a></li>',
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

    def test_redirect_user_without_usable_password(self):
        """Users without a usable password should be redirected to the manage page."""
        self.user.set_unusable_password()
        self.user.save()
        self.client.force_login(self.user)
        response = self.client.get(self.change_password_url, follow=True)
        self.assertRedirects(response, reverse("hidp_accounts:set_password"))

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

        # Redirect to the success page
        self.assertRedirects(response, reverse("hidp_accounts:change_password_done"))
        self.assertTemplateUsed("hidp/accounts/management/password_change_done.html")

        # Changed password mail should be sent
        self.assertEqual(1, len(mail.outbox))
        message = mail.outbox[0]
        self.assertEqual(message.to, [self.user.email])
        self.assertEqual(message.subject, "Password changed")
        self.assertIn(
            "You're receiving this email because your password has been changed.",
            message.body,
        )
        self.assertIn(
            "If you did not change your password, please reset your password"
            " immediately using this link:",
            message.body,
        )
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
        cls.set_password_url = reverse("hidp_accounts:set_password")

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
        self.assertRedirects(response, reverse("hidp_accounts:change_password"))

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

    def test_change_password(self):
        """The user's password should be set."""
        self.client.force_login(self.user)
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
        self.assertRedirects(response, reverse("hidp_accounts:set_password_done"))
        self.assertTemplateUsed("hidp/accounts/management/set_change_done.html")

        # Changed password mail should be sent
        self.assertEqual(1, len(mail.outbox))
        message = mail.outbox[0]
        self.assertEqual(message.to, [self.user.email])
        self.assertEqual(message.subject, "Password changed")
        self.assertIn(
            "You're receiving this email because your password has been changed.",
            message.body,
        )
        self.assertIn(
            "If you did not change your password, please reset your password"
            " immediately using this link:",
            message.body,
        )
        self.assertIn(
            reverse("hidp_accounts:password_reset_request"),
            message.body,
        )
