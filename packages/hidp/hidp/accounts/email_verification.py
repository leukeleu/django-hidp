from urllib.parse import urlencode

from django.urls import reverse

from . import tokens


def get_email_verification_required_url(
    user,
    *,
    next_url="",
    token_generator=tokens.email_verification_request_token_generator,
):
    url = reverse(
        "hidp_accounts:email_verification_required",
        kwargs={"token": token_generator.make_token(user)},
    )
    if next_url:
        url += f"?{urlencode({'next': next_url})}"
    return url
