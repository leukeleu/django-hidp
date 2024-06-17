#!/usr/bin/env python
import os
import sys


def runtests():
    os.environ.setdefault("DJANGO_SETTINGS_MODULE", "tests.test_settings")
    try:
        from django.core.management import execute_from_command_line  # noqa: PLC0415
    except ImportError as exc:
        raise ImportError(
            "Couldn't import Django. Are you sure it's installed and "
            "available on your PYTHONPATH environment variable? Did you "
            "forget to activate a virtual environment?"
        ) from exc
    execute_from_command_line([sys.argv[0], "test"] + sys.argv[1:])


if __name__ == "__main__":
    runtests()
