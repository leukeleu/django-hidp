from django.http import HttpResponse


def rate_limited(request, exception):
    return HttpResponse(
        content=(
            "Sorry, you have made too many requests to the server."
            " Please try again later."
        ),
        status=429,
    )
