from oauth2_provider import views as oauth2_views

from django.http import JsonResponse
from django.utils.decorators import method_decorator

from ..csp.decorators import hidp_csp_protection
from ..utils import is_registration_enabled


@method_decorator(hidp_csp_protection, name="dispatch")
class AuthorizationView(oauth2_views.AuthorizationView):
    def handle_prompt_create(self):
        # Django OAuth Toolkit sends prompt=create to the registration page
        # (OIDC_RP_INITIATED_REGISTRATION_URL). Refuse it like an unsupported
        # prompt value when registration is disabled.
        if not is_registration_enabled():
            return JsonResponse(
                {
                    "error": "invalid_request",
                    "error_description": "prompt=create is not supported",
                },
                status=400,
            )
        return super().handle_prompt_create()


@method_decorator(hidp_csp_protection, name="dispatch")
class RPInitiatedLogoutView(oauth2_views.RPInitiatedLogoutView):
    template_name = "hidp/accounts/logout_confirm.html"
