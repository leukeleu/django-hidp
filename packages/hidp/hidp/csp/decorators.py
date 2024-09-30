def hidp_csp_protection(view_func):
    def _wrapped_view(request, *args, **kwargs):
        request.hidp_csp_protection = True
        return view_func(request, *args, **kwargs)

    return _wrapped_view
