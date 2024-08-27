from unittest import mock

from django.test import RequestFactory, TestCase, override_settings
from django.utils import translation

from hidp.translations.middleware import UiLocalesMiddleware


@override_settings(LANGUAGES=[("en", "English"), ("fr", "French")])
class TestUiLocalesMiddleware(TestCase):
    client_class = RequestFactory

    def setUp(self):
        self.get_response = mock.Mock()
        self.middleware = UiLocalesMiddleware(self.get_response)

    def test_no_preference(self):
        """
        Do nothing if there is no language preference.
        """
        active_language = translation.get_language()
        response = self.middleware(self.client.get("/"))
        self.assertEqual(
            response,
            self.get_response.return_value,
        )
        self.assertEqual(active_language, translation.get_language())

    def test_drops_ui_locales_param(self):
        """
        Removes the 'ui_locales' query parameter, keeps the rest.
        """
        # This is a workaround for a bug in Django OAuth Toolkit:
        # https://github.com/jazzband/django-oauth-toolkit/issues/1468
        request = self.client.get("/?ui_locales=fr&foo=bar")
        response = self.middleware(request)
        # Does not call get_response
        self.get_response.assert_not_called()
        # Redirects to the same URL without the 'ui_locales' query parameter.
        self.assertEqual(
            response.status_code,
            302,
        )
        self.assertEqual(
            response.url,
            f'http://{request.META["SERVER_NAME"]}/?foo=bar',
        )

    def test_sets_cookie_for_supported_langauge(self):
        """
        Sets the language cookie if 'ui_locales' is present,
        and the language is supported
        """
        request = self.client.get("/?ui_locales=fr")
        response = self.middleware(request)
        # Sets the language cookie.
        self.assertEqual(
            response.cookies["hidp_language"].value,
            "fr",
        )

    def test_picks_first_supported_language(self):
        """
        Picks the first supported language if multiple are provided.
        """
        request = self.client.get("/?ui_locales=de fr-be en")
        response = self.middleware(request)
        # Sets the language cookie.
        self.assertEqual(
            response.cookies["hidp_language"].value,
            # 'de' is not supported, 'fr-be' is a variant of 'fr', so 'fr' is picked.
            "fr",
        )

    def test_ignores_unsupported_language(self):
        """
        Does not set the language cookie if the language is not supported.
        """
        request = self.client.get("/?ui_locales=de")
        response = self.middleware(request)
        # Does not set the language cookie.
        self.assertNotIn(
            "hidp_language",
            response.cookies,
        )

    def test_activates_language(self):
        """
        Activates the language if it is supported.
        """
        request = self.client.get("/", HTTP_COOKIE="hidp_language=fr")
        response = self.middleware(request)
        self.assertEqual(
            response,
            self.get_response.return_value,
        )
        self.assertEqual(
            translation.get_language(),
            "fr",
        )

    def test_does_not_activate_unsupported_language(self):
        """
        Does not activate the language if it is not supported.
        """
        request = self.client.get("/", HTTP_COOKIE="hidp_language=de")
        response = self.middleware(request)
        self.assertEqual(
            response,
            self.get_response.return_value,
        )
        self.assertNotEqual(
            translation.get_language(),
            "de",
        )
