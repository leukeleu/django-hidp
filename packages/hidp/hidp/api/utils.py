from rest_framework import exceptions
from rest_framework.authentication import CSRFCheck, SessionAuthentication
from rest_framework.permissions import SAFE_METHODS, BasePermission
from rest_framework.views import APIView

from django.apps import apps
from django.utils.translation import gettext as _


class CSRFProtectedAPIView(APIView):
    """
    API view that enforces CSRF validation on every request, as a DRF 403.

    DRF only checks CSRF for users that `SessionAuthentication` authenticated.
    """

    def initial(self, request, *args, **kwargs):
        check = CSRFCheck(lambda request: None)
        # Populates request.META["CSRF_COOKIE"], which process_view reads.
        check.process_request(request)
        if reason := check.process_view(request, None, (), {}):
            raise exceptions.PermissionDenied(
                _("CSRF Failed: %(reason)s") % {"reason": reason}
            )
        super().initial(request, *args, **kwargs)


def get_authentication_classes():
    """
    Return the authentication classes for API views that act on the current user.

    OAuth2 bearer tokens are only accepted when HIdP's OIDC provider is installed.
    """
    authentication_classes = [SessionAuthentication]
    if apps.is_installed("hidp.oidc_provider"):
        from oauth2_provider.contrib.rest_framework import (  # noqa: PLC0415
            OAuth2Authentication,
        )

        authentication_classes.append(OAuth2Authentication)
    return authentication_classes


class AccessTokenScopePermission(BasePermission):
    """
    Let an OAuth2 access token read the user, but never change it.

    The token needs the `profile` and `email` scopes, which cover the fields of the
    user. Requests authenticated by the session are not affected.
    """

    user_scopes = ["profile", "email"]

    def has_permission(self, request, view):
        if request.auth is None:
            return True
        # Django OAuth Toolkit accepts the tokens of deactivated users.
        return (
            request.user.is_active
            and request.method in SAFE_METHODS
            and request.auth.allow_scopes(self.user_scopes)
        )
