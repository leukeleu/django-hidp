import secrets


class CSPMiddleware:
    """Set Content Security Policy header and add generated nonce to request."""

    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        response = self.get_response(request)

        # Do nothing if CSP header is already set or `hidp_csp_protection` variable
        # is not set on view.
        if "Content-Security-Policy" in response.headers or not hasattr(
            request, "hidp_csp_protection"
        ):
            return response

        request.hidp_csp_nonce = secrets.token_urlsafe(128)
        response["Content-Security-Policy"] = (
            f"script-src 'nonce-{request.hidp_csp_nonce}' 'strict-dynamic';"
            f" object-src 'none'; base-uri 'none';"
        )
        return response
