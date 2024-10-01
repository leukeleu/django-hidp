import secrets


def hidp_csp_protection(view_func):
    def _wrapped_view(request, *args, **kwargs):
        request.hidp_csp_nonce = secrets.token_urlsafe(128)
        response = view_func(request, *args, **kwargs)

        if "Content-Security-Policy" not in response.headers:
            response.headers["Content-Security-Policy"] = (
                f"script-src 'nonce-{request.hidp_csp_nonce}' 'strict-dynamic';"
                f" object-src 'none'; base-uri 'none';"
            )
        return response

    return _wrapped_view
