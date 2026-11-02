from http import HTTPStatus

from django.http import HttpResponse, JsonResponse
from django.utils.translation import gettext_lazy as _
from django.views.decorators.cache import never_cache

RATE_LIMITED_MESSAGE = _(
    "Sorry, you have made too many requests to the server. Please try again later."
)


def rate_limited(request, exception):
    return HttpResponse(
        content=str(RATE_LIMITED_MESSAGE),
        status=HTTPStatus.TOO_MANY_REQUESTS,
    )


@never_cache
def rate_limited_api(request, exception):
    return JsonResponse(
        {"detail": str(RATE_LIMITED_MESSAGE)},
        status=HTTPStatus.TOO_MANY_REQUESTS,
    )
