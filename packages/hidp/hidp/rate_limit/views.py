from http import HTTPStatus

from django.http import HttpResponse, JsonResponse
from django.utils.cache import add_never_cache_headers

RATE_LIMITED_MESSAGE = (
    "Sorry, you have made too many requests to the server. Please try again later."
)


def rate_limited(request, exception):
    return HttpResponse(
        content=RATE_LIMITED_MESSAGE,
        status=HTTPStatus.TOO_MANY_REQUESTS,
    )


def rate_limited_api(request, exception):
    response = JsonResponse(
        {"detail": RATE_LIMITED_MESSAGE},
        status=HTTPStatus.TOO_MANY_REQUESTS,
    )
    add_never_cache_headers(response)
    return response
