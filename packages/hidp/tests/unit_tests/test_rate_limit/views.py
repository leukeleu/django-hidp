from django_ratelimit.exceptions import Ratelimited
from rest_framework.views import APIView


def rate_limited_view(request):
    raise Ratelimited


class RateLimitedAPIView(APIView):
    def dispatch(self, request, *args, **kwargs):
        # Raised outside of DRF's exception handling, like the API rate limits.
        raise Ratelimited
