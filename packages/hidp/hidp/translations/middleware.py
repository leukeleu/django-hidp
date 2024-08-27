import contextlib

from django.http import HttpResponseRedirect
from django.utils import translation


def _get_supported_language_variant(language_code):
    with contextlib.suppress(LookupError):
        return translation.get_supported_language_variant(language_code)


def _get_language_from_cookie(request):
    language = request.COOKIES.get(UiLocalesMiddleware.LANGUAGE_COOKIE_NAME)
    if language and _get_supported_language_variant(language):
        return language
    return None


def _get_language_from_ui_locales(request):
    ui_locales = request.GET.get("ui_locales", "").strip()
    for ui_locale in ui_locales.split():
        if language := _get_supported_language_variant(ui_locale):
            return language
    return None


class UiLocalesMiddleware:
    """
    Middleware that sets a cookie and activated the language based on the 'ui_locales'
    query parameter.

    As a workaround for a bug in Django Oauth Toolkit, the middleware also makes sure
    that the 'ui_locales' query parameter is removed from the URL.
    """

    LANGUAGE_COOKIE_NAME = "hidp_language"

    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        if "ui_locales" in request.GET:
            # Remove the ui_locales query parameter from the URL.
            # This is a workaround for a bug in Django OAuth Toolkit:
            # https://github.com/jazzband/django-oauth-toolkit/issues/1468
            query = request.GET.copy()
            query.pop("ui_locales")
            request.META["QUERY_STRING"] = query.urlencode()
            response = HttpResponseRedirect(request.build_absolute_uri())

            # Set the language cookie if the language is supported.
            if language := _get_language_from_ui_locales(request):
                # Set the language cookie.
                response.set_cookie(
                    self.LANGUAGE_COOKIE_NAME,
                    language,
                )

            return response

        if language := _get_language_from_cookie(request):
            translation.activate(language)

        return self.get_response(request)
