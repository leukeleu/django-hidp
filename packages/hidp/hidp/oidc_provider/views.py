from oauth2_provider import views as oauth2_views

from django.http import JsonResponse
from django.utils.decorators import method_decorator

from ..csp.decorators import hidp_csp_protection
from ..utils import is_registration_enabled
from .frontend import FrontendPageMixin


@method_decorator(hidp_csp_protection, name="dispatch")
class AuthorizationView(FrontendPageMixin, oauth2_views.AuthorizationView):
    frontend_url_key = "oidc_provider_consent"
    page_name = "consent"

    def get_page(self, context):
        page = super().get_page(context)
        if page["page"] == self.page_name:
            page["scopes"] = [
                {"scope": scope, "description": description}
                for scope, description in zip(
                    context.get("scopes", []),
                    context.get("scopes_descriptions", []),
                    strict=True,
                )
            ]
        return page

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
class RPInitiatedLogoutView(FrontendPageMixin, oauth2_views.RPInitiatedLogoutView):
    frontend_url_key = "oidc_provider_logout"
    page_name = "logout"
    template_name = "hidp/accounts/logout_confirm.html"
