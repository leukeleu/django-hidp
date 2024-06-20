from datetime import UTC

from oauth2_provider import oauth2_validators

from django.utils.timezone import localtime


class OAuth2Validator(oauth2_validators.OAuth2Validator):
    # Maps OIDC claims to scopes. This is used to determine which claims to include
    # in the ID token and user info response.
    oidc_claim_scope = oauth2_validators.OAuth2Validator.oidc_claim_scope

    def get_additional_claims(self, request):
        """
        Map user attributes to OIDC claims.

        These claims are included in the ID token and user info response.

        Only those claims that belong to the requested scopes are included.
        This means that, for example, if the client only requests the `openid` scope,
        none of the additional claims will be included in the ID token.

        The mapping of claims to scopes is defined in the `oidc_claim_scope` dictionary.
        """
        return super().get_additional_claims(request) | {
            "name": request.user.get_full_name(),
            "given_name": request.user.first_name,
            "family_name": request.user.last_name,
            "updated_at": int(localtime(request.user.last_modified, UTC).timestamp()),
            "email": request.user.email,
            "email_verified": request.user.email_verified is not None,
        }
