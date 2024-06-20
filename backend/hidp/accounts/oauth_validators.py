from datetime import UTC

from oauth2_provider import oauth2_validators

from django.utils.timezone import localtime


class OAuth2Validator(oauth2_validators.OAuth2Validator):
    def get_additional_claims(self, request):
        return super().get_additional_claims(request) | {
            "name": request.user.get_full_name(),
            "given_name": request.user.first_name,
            "family_name": request.user.last_name,
            "updated_at": int(localtime(request.user.last_modified, UTC).timestamp()),
            "email": request.user.email,
            "email_verified": request.user.email_verified is not None,
        }
