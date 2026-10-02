from http import HTTPStatus

from django.http import HttpResponse, JsonResponse
from django.views.decorators.cache import never_cache

RATE_LIMITED_MESSAGE = (
    "Sorry, you have made too many requests to the server. Please try again later."
)


def rate_limited(request, exception):
    return HttpResponse(
        content=RATE_LIMITED_MESSAGE,
        status=HTTPStatus.TOO_MANY_REQUESTS,
    )


@never_cache
def rate_limited_api(request, exception):
    return JsonResponse(
        {"detail": RATE_LIMITED_MESSAGE},
        status=HTTPStatus.TOO_MANY_REQUESTS,
    )
