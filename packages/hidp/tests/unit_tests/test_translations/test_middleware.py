from unittest import mock

from django.http import HttpResponse
from django.test import RequestFactory, TestCase, override_settings
from django.utils import translation

from hidp.oidc_provider.middleware import UiLocalesMiddleware


@override_settings(LANGUAGES=[("en", "English"), ("fr", "French")])
class TestUiLocalesMiddleware(TestCase):
    client_class = RequestFactory

    def setUp(self):
        self.get_response = mock.Mock(return_value=HttpResponse())
        self.middleware = UiLocalesMiddleware(self.get_response)

    def test_no_preference(self):
        """Do nothing if there is no language preference."""
        active_language = translation.get_language()
        response = self.middleware(self.client.get("/"))
        self.assertEqual(
            response,
            self.get_response.return_value,
        )
        self.assertEqual(active_language, translation.get_language())
        self.assertNotIn(
            "django_language",
            response.cookies,
        )

    def test_sets_cookie_for_supported_langauge(self):
        """Sets the language cookie if the param contains a supported language."""
        request = self.client.get("/?ui_locales=fr")
        response = self.middleware(request)
        # Sets the language cookie.
        self.assertEqual(
            response.cookies["django_language"].value,
            "fr",
        )

    def test_picks_first_supported_language(self):
        """Picks the first supported language if multiple are provided."""
        request = self.client.get("/?ui_locales=de fr-be en")
        response = self.middleware(request)
        # Sets the language cookie.
        self.assertEqual(
            response.cookies["django_language"].value,
            # 'de' is not supported, 'fr-be' is a variant of 'fr', so 'fr' is picked.
            "fr",
        )

    def test_ignores_unsupported_language(self):
        """Does not set the language cookie if the language is not supported."""
        request = self.client.get("/?ui_locales=de")
        response = self.middleware(request)
        # Does not set the language cookie.
        self.assertNotIn(
            "django_language",
            response.cookies,
        )
