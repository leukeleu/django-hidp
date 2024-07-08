from django_ratelimit.exceptions import Ratelimited


def rate_limited_view(request):
    raise Ratelimited
