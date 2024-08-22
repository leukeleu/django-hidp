from django.conf import settings
from django.http import HttpResponseRedirect
from django.utils import translation


class UiLocalesMiddleware:
    """
    Middleware that sets the language based on the 'ui_locales' query parameter.

    As a workaround for a bug in Django Oauth Toolkit, the middleware also makes sure
    that the 'ui_locales' query parameter is removed from the URL.
    """

    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        ui_locales = request.GET.get("ui_locales", "")

        if ui_locales:
            # Removes the ui_locales query parameter from the URL.
            # This is a workaround for a bug in Django OAuth Toolkit:
            # https://github.com/jazzband/django-oauth-toolkit/issues/1468
            query = request.GET.copy()
            query.pop("ui_locales")
            request.META["QUERY_STRING"] = query.urlencode()
            response = HttpResponseRedirect(request.build_absolute_uri())
        else:
            response = self.get_response(request)

        for ui_locale in ui_locales.split():
            if not translation.trans_real.language_code_re.search(ui_locale):
                continue
            try:
                language = translation.get_supported_language_variant(ui_locale)
            except LookupError:
                continue
            else:
                response.set_cookie(settings.LANGUAGE_COOKIE_NAME, language)

        return response
