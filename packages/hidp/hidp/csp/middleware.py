import secrets


class CSPMiddleware:
    """Set Content Security Policy header and add generated nonce to request."""

    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        request.hidp_csp_nonce = secrets.token_urlsafe(128)
        response = self.get_response(request)
        if "Content-Security-Policy" not in response.headers:
            response["Content-Security-Policy"] = (
                f"script-src 'nonce-{request.hidp_csp_nonce}' 'strict-dynamic';"
                f" object-src 'none'; base-uri 'none';"
            )
        return response
