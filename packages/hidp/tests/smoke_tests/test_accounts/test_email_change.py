from django.test import TestCase
from django.urls import reverse

from hidp.accounts.forms import EmailChangeRequestForm
from hidp.accounts.models import EmailChangeRequest
from hidp.test.factories import user_factories


class TestEmailChangeRequest(TestCase):
    @classmethod
    def setUpTestData(cls):
        cls.user = user_factories.UserFactory()
        cls.url = reverse("hidp_accounts:email_change_request")

    def setUp(self):
        self.client.force_login(self.user)

    def test_get_unauthenticated(self):
        self.client.logout()
        response = self.client.get(self.url)

        self.assertEqual(response.status_code, 302)

    def test_get(self):
        response = self.client.get(self.url)

        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(
            response, "hidp/accounts/management/email_change_request.html"
        )

    def test_user_requests_email_change(self):
        response = self.client.post(
            self.url,
            {
                "password": "P@ssw0rd!",
                "proposed_email": "newemail@example.com",
            },
            follow=True,
        )

        self.assertRedirects(
            response, reverse("hidp_accounts:email_change_request_sent")
        )
        self.assertTemplateUsed(
            response, "hidp/accounts/management/email_change_request_sent.html"
        )

        # EmailChangeRequest should be created
        self.assertTrue(
            EmailChangeRequest.objects.filter(
                user=self.user,
                proposed_email="newemail@example.com",
            ).exists()
        )

class TestEmailChangeRequestForm(TestCase):
    @classmethod
    def setUpTestData(cls):
        cls.user = user_factories.UserFactory()
        cls.existing_email_change_request = user_factories.EmailChangeRequestFactory(
            user=cls.user
        )

    def test_form_invalid_password(self):
        form = EmailChangeRequestForm(
            user=self.user,
            data={
                "password": "invalid",
                "proposed_email": "newemail@example.com",
            },
        )
        self.assertFalse(form.is_valid())

    def test_form_valid(self):
        form = EmailChangeRequestForm(
            user=self.user,
            data={
                "password": "P@ssw0rd!",
                "proposed_email": "newemail@example.com",
            },
        )
        self.assertTrue(form.is_valid())

        form.save()

        # Old EmailChangeRequest should be deleted
        self.assertFalse(
            EmailChangeRequest.objects.filter(
                id=self.existing_email_change_request.pk
            ).exists()
        )

        # New EmailChangeRequest should be created
        self.assertTrue(
            EmailChangeRequest.objects.filter(
                user=self.user,
                proposed_email="newemail@example.com",
            ).exists()
        )
