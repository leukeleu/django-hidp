from django.core.management import BaseCommand

from ...email_verification import remove_stale_unverified_accounts


class Command(BaseCommand):
    DEFAULT_MAX_DAYS = 90
    help = (
        "Remove accounts that have not been verified within"
        " a specific number of days after creation"
    )

    def add_arguments(self, parser):
        parser.add_argument(
            "--days",
            type=int,
            default=self.DEFAULT_MAX_DAYS,
            help=(
                f"Maximum number of days an account is allowed to be unverified:"
                f" defaults to {self.DEFAULT_MAX_DAYS}."
            ),
        )

        parser.add_argument(
            "--dry-run",
            action="store_true",
            help=(
                "Show the number of accounts that would be removed,"
                " without performing the removal."
            ),
        )

    def handle(self, *args, days, dry_run, **options):
        self.stdout.write(
            f"Removing accounts that have not been verified within {days} days..."
        )

        unverified_users_count = remove_stale_unverified_accounts(
            days=days, dry_run=dry_run
        )

        if dry_run:
            self.stdout.write(
                self.style.WARNING(
                    f"{unverified_users_count} unverified account(s) would be removed."
                )
            )
        else:
            self.stdout.write(
                self.style.SUCCESS(
                    f"Successfully removed {unverified_users_count}"
                    f" unverified account(s)."
                )
            )
