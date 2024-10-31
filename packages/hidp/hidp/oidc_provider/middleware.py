import contextlib

from django.conf import settings
from django.http import HttpResponseRedirect
from django.utils import translation


def _get_supported_language_variant(language_code):
    with contextlib.suppress(LookupError):
        return translation.get_supported_language_variant(language_code)


def _get_language_from_ui_locales(request):
    ui_locales = request.GET.get("ui_locales", "").strip()
    for ui_locale in ui_locales.split():
        if not translation.check_for_language(ui_locale):
            continue
        if lang_code := _get_supported_language_variant(ui_locale):
            return lang_code
    return None


class UiLocalesMiddleware:
    """
    Set the language preference based on the 'ui_locales' parameter in the query.

    The 'ui_locales' parameter is a space-separated list of language tags, ordered by
    preference. The first language tag that is supported by the application is stored
    in a cookie. If no supported language is found, the language cookie is not set.

    This cookie is used by Django's LocaleMiddleware to set the language for
    the request and may also be set using Django's set_language view.
    """

    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        if lang_code := _get_language_from_ui_locales(request):
            # The 'ui_locales' parameter contains a supported language.
            # Remove the parameter from the query string:
            query = request.GET.copy()
            query.pop("ui_locales")
            request.META["QUERY_STRING"] = query.urlencode()
            response = HttpResponseRedirect(request.build_absolute_uri())
            # Set the language preference cookie,
            # exactly as Django's set_language view does:
            response.set_cookie(
                settings.LANGUAGE_COOKIE_NAME,
                lang_code,
                max_age=settings.LANGUAGE_COOKIE_AGE,
                path=settings.LANGUAGE_COOKIE_PATH,
                domain=settings.LANGUAGE_COOKIE_DOMAIN,
                secure=settings.LANGUAGE_COOKIE_SECURE,
                httponly=settings.LANGUAGE_COOKIE_HTTPONLY,
                samesite=settings.LANGUAGE_COOKIE_SAMESITE,
            )
            return response
        return self.get_response(request)
