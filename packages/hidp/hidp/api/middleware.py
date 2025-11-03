from django.utils import timezone
from django.utils.deprecation import MiddlewareMixin


class AugmentSessionMiddleware(MiddlewareMixin):
    """
    Adds additional session information to the request session.

    The following fields are added:
    - `created_at` the datetime this session was first used
    - `last_active` the latest datetime this session was used
    - `user_agent` the last user agent of the client that used this session
    - `ip_address` the last ip address of the client  that used this session
    """

    @classmethod
    def process_request(cls, request):
        if "created_at" not in request.session:
            request.session["created_at"] = timezone.now().isoformat()

        request.session["last_active"] = timezone.now().isoformat()
        request.session["user_agent"] = request.headers.get("User-Agent")
        request.session["ip_address"] = request.META.get("REMOTE_ADDR")
