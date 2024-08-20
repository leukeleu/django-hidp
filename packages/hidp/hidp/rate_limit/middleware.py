from django_ratelimit.exceptions import Ratelimited
from django_ratelimit.middleware import RatelimitMiddleware as _RatelimitMiddleware

from ..rate_limit.views import rate_limited


class RateLimitMiddleware(_RatelimitMiddleware):
    rate_limited_view = rate_limited

    def process_exception(self, request, exception):
        if not isinstance(exception, Ratelimited):
            return None
        return self.rate_limited_view(exception)
