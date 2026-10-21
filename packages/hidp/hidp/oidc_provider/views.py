from oauth2_provider import views as oauth2_views

from django.contrib.auth.models import AnonymousUser
from django.utils.decorators import method_decorator

from ..csp.decorators import hidp_csp_protection


def _has_prompt_create(request):
    # Check if the prompt=create parameter is present in the request.
    # This parameter is used to explicitly signal that user desires to
    # create a new account rather than authenticate using an existing identity.
    # https://openid.net/specs/openid-connect-prompt-create-1_0.html
    return request.GET.get("prompt") == "create"


@method_decorator(hidp_csp_protection, name="dispatch")
class AuthorizationView(oauth2_views.AuthorizationView):
    def get(self, request, *args, **kwargs):
        if _has_prompt_create(request):
            # Switch request.user to AnonymousUser. This forces handle_no_permission
            # to redirect to the registration page (via handle_prompt_create) instead
            # of treating the prompt as a no-op if a user is currently logged-in.
            self.request.user = AnonymousUser()
            return self.handle_no_permission()
        return super().get(request, *args, **kwargs)


@method_decorator(hidp_csp_protection, name="dispatch")
class RPInitiatedLogoutView(oauth2_views.RPInitiatedLogoutView):
    template_name = "hidp/accounts/logout_confirm.html"
