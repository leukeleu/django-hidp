from django.core.management import BaseCommand

from ...email_change import remove_complete_and_stale_email_change_requests


class Command(BaseCommand):
    DEFAULT_MAX_DAYS = 7
    help = (
        "Remove completed email change requests and requests that have not been"
        " completed within a specific number of days after creation"
    )

    def add_arguments(self, parser):
        parser.add_argument(
            "--days",
            type=int,
            default=self.DEFAULT_MAX_DAYS,
            help=(
                f"Maximum number of days an email change request is allowed to be"
                f" incomplete: defaults to {self.DEFAULT_MAX_DAYS}."
            ),
        )

        parser.add_argument(
            "--dry-run",
            action="store_true",
            help=(
                "Show the number of email change requests that would be removed,"
                " without performing the removal."
            ),
        )

    def handle(self, *args, days, dry_run, **options):
        self.stdout.write(
            f"Removing completed email change requests and requests that have not been"
            f" completed within {days} days..."
        )

        complete_and_stale_email_change_requests_count = (
            remove_complete_and_stale_email_change_requests(days=days, dry_run=dry_run)
        )

        if dry_run:
            self.stdout.write(
                self.style.WARNING(
                    f"{complete_and_stale_email_change_requests_count} completed and/or"
                    " stale email change request(s) would be removed."
                )
            )
        else:
            self.stdout.write(
                self.style.SUCCESS(
                    f"Successfully removed"
                    f" {complete_and_stale_email_change_requests_count} completed"
                    f" and/or stale email change request(s)."
                )
            )
