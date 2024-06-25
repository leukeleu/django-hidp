from django.test import TestCase
from django.urls import reverse


class TestRoot(TestCase):
    def test_root(self):
        response = self.client.get("/")
        self.assertRedirects(
            response, reverse("hidp_accounts:login"), fetch_redirect_response=False
        )
