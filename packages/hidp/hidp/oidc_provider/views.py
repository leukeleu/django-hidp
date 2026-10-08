from oauth2_provider import views as oauth2_views

from django.contrib.auth.models import AnonymousUser
from django.http import JsonResponse
from django.utils.decorators import method_decorator

from ..csp.decorators import hidp_csp_protection
from ..utils import is_registration_enabled
from .frontend import FrontendPageMixin


def _has_prompt_create(request):
    # Check if the prompt=create parameter is present in the request.
    # This parameter is used to explicitly signal that user desires to
    # create a new account rather than authenticate using an existing identity.
    # https://openid.net/specs/openid-connect-prompt-create-1_0.html
    return request.GET.get("prompt") == "create"


@method_decorator(hidp_csp_protection, name="dispatch")
class AuthorizationView(FrontendPageMixin, oauth2_views.AuthorizationView):
    frontend_step = "oidc_provider_consent"
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

    def get(self, request, *args, **kwargs):
        if _has_prompt_create(request):
            # Switch request.user to AnonymousUser. This forces handle_no_permission
            # to redirect to the registration page (via handle_prompt_create) instead
            # of treating the prompt as a no-op if a user is currently logged-in.
            self.request.user = AnonymousUser()
            return self.handle_no_permission()
        return super().get(request, *args, **kwargs)

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
    frontend_step = "oidc_provider_logout"
    page_name = "logout"
    template_name = "hidp/accounts/logout_confirm.html"
