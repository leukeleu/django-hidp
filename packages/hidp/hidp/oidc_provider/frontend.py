"""
The pages of HIdP's OIDC provider, on the frontend.

A view that would render a page keeps what the page shows in the session, under a
token, and redirects to the frontend URL of the page. The frontend reads it from
the API, and posts the form of the page to `action`, with the `fields` and the
choice of the user in `allow`, as the HTML page would.
"""

from datetime import timedelta

from django.http import HttpResponseRedirect

from ..federated.tokens import BaseOIDCTokenGenerator
from ..utils import get_frontend_redirect_url, has_frontend_url


class OIDCProviderPageTokenGenerator(BaseOIDCTokenGenerator):
    """Token for a page of the OIDC provider that the frontend shows."""

    key_salt = "oidc-provider-page"
    token_timeout = timedelta(minutes=10).total_seconds()


page_token_generator = OIDCProviderPageTokenGenerator()


def get_stored_page(request, token):
    """Return the page kept under `token`, or `None`."""
    if not token or not page_token_generator.check_token(token):
        return None
    return request.session.get(token)


class FrontendPageMixin:
    """
    Redirect to a frontend page instead of rendering the HTML template.

    Only when `HIDP_FRONTEND_URLS` has `frontend_url_key`. Otherwise the view
    renders its template as before.
    """

    frontend_url_key = NotImplemented
    page_name = NotImplemented

    def get_page(self, context):
        """Return what the frontend shows, with the form it posts."""
        if "form" not in context:
            # An error that cannot be sent to the client.
            error = context.get("error")
            return {
                "page": "error",
                "error": getattr(error, "error", None),
                "error_description": getattr(error, "description", None),
            }
        form = context["form"]
        application = context.get("application")
        return {
            "page": self.page_name,
            "action": self.request.path,
            "application": (
                {"name": application.name, "client_id": application.client_id}
                if application
                else None
            ),
            "fields": {
                name: form[name].value()
                for name in form.fields
                if name != "allow" and form[name].value() is not None
            },
        }

    def render_to_response(self, context, **response_kwargs):
        if not has_frontend_url(self.frontend_url_key):
            return super().render_to_response(context, **response_kwargs)
        token = page_token_generator.make_token()
        self.request.session[token] = self.get_page(context)
        return HttpResponseRedirect(
            get_frontend_redirect_url(self.request, self.frontend_url_key, token=token)
        )
