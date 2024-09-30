def hidp_csp_nonce(request):
    return {
        "hidp_csp_nonce": getattr(request, "hidp_csp_nonce", None),
    }
