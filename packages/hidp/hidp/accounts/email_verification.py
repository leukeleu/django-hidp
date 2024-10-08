from datetime import timedelta
from urllib.parse import urlencode

from django.contrib.auth import get_user_model
from django.urls import reverse
from django.utils import timezone

from . import tokens

UserModel = get_user_model()


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


def remove_stale_unverified_accounts(*, days=90, dry_run=False):
    """
    Remove accounts that are not verified within a given number of days after creation.

    Args:
        days (int):
            Maximum number of days an account is allowed to be
            unverified. Defaults to 90.

        dry_run (bool):
            If `True`, returns the number of accounts that would be removed,
            without performing the removal. Defaults to `False`.

    Returns:
        int:
            The number of accounts that are deleted, or would be deleted
            if `dry_run` is `True`
    """
    unverified_users = UserModel.objects.email_unverified().filter(
        date_joined__lt=timezone.now() - timedelta(days=days),
    )
    unverified_users_count = unverified_users.count()

    if not dry_run:
        unverified_users.delete()

    return unverified_users_count
