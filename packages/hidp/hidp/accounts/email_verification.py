from urllib.parse import urlencode

from django.urls import reverse

from . import tokens


def get_email_verification_required_url(user, *, next_url=""):
    url = reverse(
        "hidp_accounts:email_verification_required",
        kwargs={
            "token": tokens.email_verification_request_token_generator.make_token(user),
        },
    )
    if next_url:
        url += f"?{urlencode({'next': next_url})}"
    return url


def get_verify_email_url(user, *, next_url=""):
    url = reverse(
        "hidp_accounts:verify_email",
        kwargs={
            "token": tokens.email_verification_token_generator.make_token(user),
        },
    )
    if next_url:
        url += f"?{urlencode({'next': next_url})}"
    return url
