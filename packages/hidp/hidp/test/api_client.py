from rest_framework.test import APIClient


class CSRFEnforcingAPIClient(APIClient):
    """
    Test APIClient that enforces CSRF checks.

    By default, the DRF APIClient does not pass `enforce_csrf_checks` to its superclass.
    This results in the underlying request to have `_dont_enforce_csrf_checks` set to
    True, effectively disabling CSRF checks.
    """

    def __init__(self, **defaults):
        super().__init__(enforce_csrf_checks=True, **defaults)
        self.enforce_csrf_checks = True
