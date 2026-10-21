from django_ratelimit.exceptions import Ratelimited
from django_ratelimit.middleware import RatelimitMiddleware as _RatelimitMiddleware

from ..rate_limit.views import rate_limited, rate_limited_api
from ..utils import is_api_request


class RateLimitMiddleware(_RatelimitMiddleware):
    rate_limited_view = staticmethod(rate_limited)
    rate_limited_api_view = staticmethod(rate_limited_api)

    def process_exception(self, request, exception):
        if not isinstance(exception, Ratelimited):
            return None
        view_func = request.resolver_match.func if request.resolver_match else None
        if is_api_request(request, view_func):
            return self.rate_limited_api_view(request, exception)
        return self.rate_limited_view(request, exception)
