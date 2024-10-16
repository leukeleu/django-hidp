import fnmatch

from django.core.management.commands import makemessages


class Command(makemessages.Command):
    """Wraps Django's makemessages command to create translation files for HIdP."""

    msgmerge_options = [
        *makemessages.Command.msgmerge_options,
        "--sort-by-file",
    ]
    msguniq_options = [
        *makemessages.Command.msguniq_options,
        "--sort-by-file",
    ]
    msgattrib_options = [
        *makemessages.Command.msgattrib_options,
        "--sort-by-file",
    ]
    xgettext_options = [
        *makemessages.Command.xgettext_options,
        "--sort-by-file",
    ]

    def add_arguments(self, parser):
        super().add_arguments(parser)
        # Override default options to avoid having to specify them
        # on the command line each time.
        parser.set_defaults(
            # Process all available locales
            all=True,
            # Add location comments, but omit line numbers
            add_location="file",
            # Do not keep obsolete messages
            no_obsolete=True,
            # Do not wrap long messages
            no_wrap=True,
            # Do not remove the .pot file
            keep_pot=True,
            # Additional ignore patterns
            ignore_patterns=[
                # Ignore editable install artifact
                "*.egg-info/*",
                # Ignore docs and tests
                "docs/*",
                "tests/*",
            ],
        )

    def find_files(self, root):
        # The additional ignore patters are not enough to exclude all
        # unwanted files, things like Makefile, README are still found.
        # Instead of adding more ignore patterns, it is easier to just
        # remove any file that is not nested in the hidp package directory.
        return [
            file
            for file in super().find_files(root)
            if fnmatch.fnmatchcase(file.path, f"{root}/hidp/*")
        ]

    def remove_potfiles(self):
        # Even though keep_pot is set to True, the default implementation
        # still removes the .pot file at the start of the process.
        # We do not want this, as it is customized to remove some of
        # the default (and in our opinion, pointless) comments and headers.
        pass
