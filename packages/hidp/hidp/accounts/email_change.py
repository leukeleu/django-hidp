from datetime import timedelta
from enum import StrEnum, auto

from django.db.models import Q
from django.utils import timezone

from .models import EmailChangeRequest


class Recipient(StrEnum):
    CURRENT_EMAIL = auto()
    PROPOSED_EMAIL = auto()


def remove_complete_and_stale_email_change_requests(*, days=7, dry_run=False):
    """
    Remove completed and stale email change requests.

    Args:
        days (int):
            Maximum number of days an email change request is allowed to be
            incomplete. Defaults to 7.

        dry_run (bool):
            If `True`, returns the number of email change requests that would be
            removed, without performing the removal. Defaults to `False`.

    Returns:
        int:
            The number of email change requests that are deleted, or would be deleted
            if `dry_run` is `True`
    """
    complete_and_stale_email_change_requests = EmailChangeRequest.objects.filter(
        Q(confirmed_by_current_email=True, confirmed_by_proposed_email=True)
        | Q(created_at__lt=timezone.now() - timedelta(days=days)),
    )
    complete_and_stale_email_change_requests_count = (
        complete_and_stale_email_change_requests.count()
    )

    if not dry_run:
        complete_and_stale_email_change_requests.delete()

    return complete_and_stale_email_change_requests_count
