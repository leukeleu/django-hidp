from django_ratelimit.exceptions import Ratelimited
from django_ratelimit.middleware import RatelimitMiddleware as _RatelimitMiddleware

from ..rate_limit.views import rate_limited, rate_limited_api
from ..utils import is_api_view


class RateLimitMiddleware(_RatelimitMiddleware):
    rate_limited_view = staticmethod(rate_limited)
    rate_limited_api_view = staticmethod(rate_limited_api)

    def process_exception(self, request, exception):
        if not isinstance(exception, Ratelimited):
            return None
        resolver_match = getattr(request, "resolver_match", None)
        if resolver_match is not None and is_api_view(resolver_match.func):
            return self.rate_limited_api_view(request, exception)
        return self.rate_limited_view(request, exception)
