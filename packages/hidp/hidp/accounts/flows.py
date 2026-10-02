"""Account side effects shared by the HTML views and the API."""

import logging

from datetime import timedelta

from django.contrib.auth import get_user_model, update_session_auth_hash
from django.db import IntegrityError, transaction
from django.utils import timezone

from . import auth as hidp_auth
from .email_change import Recipient

logger = logging.getLogger(__name__)
UserModel = get_user_model()

REAUTHENTICATION_DELTA = timedelta(minutes=5)


def register(form):
    """
    Save the user of a valid `UserCreationForm`.

    Returns the existing user when the email address is taken, so the caller can
    respond the same way whether or not an account exists.
    """
    try:
        with transaction.atomic():
            return form.save()
    except IntegrityError:
        return UserModel.objects.get(email__iexact=form.cleaned_data["email"])


def send_registration_email(user, *, verification_mailer, account_exists_mailer):
    """Send the verification email, or tell an existing user they have an account."""
    try:
        if not user.email_verified:
            verification_mailer(user).send()
        elif user.is_active:
            account_exists_mailer(user).send()
    except Exception:
        # Do not leak the existence of the user.
        logger.exception("Failed to send verification email.")


def login(request, user):
    """Log in a user with a verified email address, and return whether it did."""
    if user.email_verified:
        hidp_auth.login(request, user)
        return True
    return False


def send_password_reset_email(user, *, password_reset_mailer, set_password_mailer):
    """Send a password reset link, or a set password link to a user without one."""
    mailer = (
        password_reset_mailer if user.has_usable_password() else set_password_mailer
    )
    try:
        mailer(user).send()
    except Exception:
        # Do not leak the existence of the user.
        logger.exception("Failed to send password (re)set email.")


def change_password(request, form):
    """Save the new password of a valid password form, keeping the session valid."""
    user = form.save()
    update_session_auth_hash(request, user)
    return user


def requires_reauthentication(user, *, delta=REAUTHENTICATION_DELTA):
    """Whether `user` must log in again before setting a password."""
    return user.last_login is None or user.last_login < timezone.now() - delta


def send_email_change_emails(
    user,
    email_change_request,
    *,
    email_change_request_mailer,
    proposed_email_exists_mailer,
):
    """
    Ask the current and proposed email addresses to confirm the change.

    An existing account at the proposed address is told so, unless it is inactive.
    """
    email_change_request_mailer(
        user,
        email_change_request=email_change_request,
        recipient=Recipient.CURRENT_EMAIL,
    ).send()

    existing_user = UserModel.objects.filter(
        email__iexact=email_change_request.proposed_email
    ).first()
    if existing_user and not existing_user.is_active:
        return
    mailer = (
        proposed_email_exists_mailer if existing_user else email_change_request_mailer
    )
    mailer(
        user,
        email_change_request=email_change_request,
        recipient=Recipient.PROPOSED_EMAIL,
    ).send()


def confirm_email_change(form):
    """Save a valid `EmailChangeConfirmForm`, or return `None` if the email is taken."""
    try:
        return form.save()
    except IntegrityError:
        return None
