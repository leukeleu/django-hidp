import json

from django_ratelimit.core import user_or_ip


def username_rate_limit_key(group, request):
    """Rate limit key for the case-folded `username` in a JSON or form body."""
    if request.content_type == "application/json":
        try:
            data = json.loads(request.body)
        except (UnicodeDecodeError, ValueError):
            return ""
        username = data.get("username", "") if isinstance(data, dict) else ""
    else:
        username = request.POST.get("username", "")
    return str(username).strip().casefold()


def ip_username_rate_limit_key(group, request):
    """Rate limit key for a `username` per client, so no client locks out another."""
    return f"{user_or_ip(request)}:{username_rate_limit_key(group, request)}"
