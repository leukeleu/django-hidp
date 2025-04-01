import warnings

from django.conf import settings
from django.http import HttpResponseNotFound


def registration_enabled(view_func):
    """
    Decorator to check if registration is enabled in the Django settings.

    This decorator checks the `REGISTRATION_ENABLED` setting in the Django
    settings module. If `REGISTRATION_ENABLED` is set to `False`, the decorator
    returns a 404 (Not Found) response. If the setting is not defined, it issues
    a warning and defaults to `False`.

    Args:
        view_func (callable): The view function to be decorated. This function
                              should accept a request object and any additional
                              arguments or keyword arguments.

    Returns:
        callable: A wrapped view function that includes the registration check.

    Example:
        To use this decorator, apply it to a Django view function or class-based
        view method.

        ```python
        from django.shortcuts import render
        from .decorators import registration_enabled

        @registration_enabled
        def my_view(request):
            return render(request, 'my_template.html')
        ```

        Or, for a class-based view:

        ```python
        from django.views.generic import TemplateView
        from django.utils.decorators import method_decorator
        from .decorators import registration_enabled

        class MyView(TemplateView):
            template_name = 'my_template.html'

            @method_decorator(registration_enabled)
            def dispatch(self, *args, **kwargs):
                return super().dispatch(*args, **kwargs)
        ```

    Notes:
        - The `REGISTRATION_ENABLED` setting should be defined in your Django
          settings module (`settings.py`). If it is not defined, the decorator
          will issue a warning and default to `False`, meaning registration is
          not enabled.
        - This decorator is useful for controlling access to views that should
          only be available when registration is enabled.
        - The `HttpResponseNotFound` class is used to return a 404 response,
          indicating that the requested resource could not be found.
    """

    def _wrapped_view(request, *args, **kwargs):
        if not hasattr(settings, "REGISTRATION_ENABLED"):
            warnings.warn(
                "The REGISTRATION_ENABLED setting is not defined in settings.py. "
                "Defaulting to registration not enabled.",
                stacklevel=2,
            )
            registration_enabled = False
        else:
            registration_enabled = settings.REGISTRATION_ENABLED

        if not registration_enabled:
            return HttpResponseNotFound()
        return view_func(request, *args, **kwargs)

    return _wrapped_view
