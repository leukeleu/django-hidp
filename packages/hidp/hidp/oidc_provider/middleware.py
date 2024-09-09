import contextlib

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


def _get_language_from_request(request):
    return _get_language_from_ui_locales(request) or _get_language_from_cookie(request)


class UiLocalesMiddleware:
    """
    Handle the 'ui_locales' query parameter and set the language accordingly.

    If the 'ui_locales' parameter contains a supported language, it is activated
    and stored in a cookie for future requests.

    Otherwise, the language is set to the one stored in the cookie, if any.
    """

    LANGUAGE_COOKIE_NAME = "hidp_language"

    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        if language := _get_language_from_request(request):
            translation.activate(language)
            response = self.get_response(request)
            response.set_cookie(UiLocalesMiddleware.LANGUAGE_COOKIE_NAME, language)
            return response
        return self.get_response(request)
