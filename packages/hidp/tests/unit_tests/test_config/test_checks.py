from django.conf import settings
from django.test import TestCase, override_settings

from hidp.config import checks

# This module doubles as the ROOT_URLCONF for these tests
urlpatterns = []


# Simulate a poorly configured Django project
@override_settings(
    INSTALLED_APPS=[
        "django.contrib.contenttypes",
        "django.contrib.auth",
        "hidp.accounts",
        "tests.custom_user",
    ],
    AUTH_USER_MODEL="auth.User",
    MIDDLEWARE=[],
    USE_TZ=False,
    OAUTH2_PROVIDER=None,
    ROOT_URLCONF=__name__,  # This module is the ROOT_URLCONF
)
class TestConfigChecks(TestCase):
    def test_required_apps_not_installed(self):
        self.assertEqual(
            checks.check_installed_apps(),
            [
                checks.E001,
            ],
            msg="Expected an error because of missing required apps.",
        )

    def test_required_middlewares_not_installed(self):
        self.assertEqual(
            checks.check_middleware(),
            [
                checks.E002,
            ],
        )

    def test_use_tz_not_set(self):
        self.assertEqual(
            checks.check_use_tz(),
            [
                checks.E003,
            ],
        )

    def test_user_model_not_set_correctly(self):
        self.assertEqual(
            checks.check_user_model(),
            [
                checks.E004,
            ],
        )

    def test_oauth2_provider_not_configured(self):
        self.assertEqual(
            checks.check_oauth2_provider(),
            [
                checks.E005,
            ],
        )

    def test_urls_not_configured(self):
        self.assertEqual(
            checks.check_login_url(),
            [
                checks.E006,
            ],
        )

    def test_oidc_provider_apps_not_installed(self):
        self.assertEqual(
            checks.check_oidc_provider_installed_apps(),
            [
                checks.E008,
            ],
        )

    def test_django_otp_installed_but_hidp_otp_not_installed(self):
        self.assertEqual(
            checks.check_hidp_otp_installed_apps_when_django_otp_installed(),
            [
                checks.W001,
            ],
        )

    def test_otp_required_apps_not_installed_not_triggered(self):
        self.assertEqual(
            checks.check_otp_installed_apps(),
            [],
        )

    @override_settings(INSTALLED_APPS=["hidp.otp"])
    def test_otp_required_apps_not_installed(self):
        self.assertEqual(
            checks.check_otp_installed_apps(),
            [
                checks.E009,
            ],
        )

    def test_otp_required_middleware_not_installed_not_triggered(self):
        self.assertEqual(
            checks.check_otp_middleware(),
            [],
        )

    @override_settings(INSTALLED_APPS=["hidp.otp"])
    def test_otp_required_middleware_not_installed(self):
        self.assertEqual(
            checks.check_otp_middleware(),
            [
                checks.E010,
            ],
        )


VALID_FRONTEND_URLS = {
    "email_verification": "/verify/{token}/",
    "password_reset": "https://app.example.com/reset/{uidb64}/{token}/",
    "password_reset_request": "/reset/",
    "set_password": "/set-password/",
    "email_change_confirm": "/change-email/{token}/",
    "email_change_cancel": "/change-email/cancel/",
}


class TestFrontendUrlsCheck(TestCase):
    """HIDP_FRONTEND_URLS must hold a valid URL template for every emailed link."""

    def _check_ids(self):
        return [error.id for error in checks.check_api_frontend_urls()]

    @override_settings(ROOT_URLCONF=__name__)
    def test_not_checked_without_headless_api(self):
        with self.settings():
            del settings.HIDP_FRONTEND_URLS
            self.assertEqual(checks.check_api_frontend_urls(), [])

    @override_settings(ROOT_URLCONF="hidp.config.urls")
    def test_not_checked_for_the_user_endpoint_alone(self):
        # OAuth2 clients use api/users/, which sends no emails.
        with self.settings():
            del settings.HIDP_FRONTEND_URLS
            self.assertEqual(checks.check_api_frontend_urls(), [])

    @override_settings(HIDP_FRONTEND_URLS=VALID_FRONTEND_URLS)
    def test_valid_frontend_urls(self):
        self.assertEqual(checks.check_api_frontend_urls(), [])

    def test_setting_missing(self):
        with self.settings():
            del settings.HIDP_FRONTEND_URLS
            self.assertEqual(self._check_ids(), ["hidp.E011"])

    @override_settings(HIDP_FRONTEND_URLS=["/verify/{token}/"])
    def test_setting_not_a_dict(self):
        self.assertEqual(self._check_ids(), ["hidp.E011"])

    def test_key_missing(self):
        frontend_urls = VALID_FRONTEND_URLS.copy()
        del frontend_urls["email_change_cancel"]
        with self.settings(HIDP_FRONTEND_URLS=frontend_urls):
            errors = checks.check_api_frontend_urls()
        self.assertEqual([error.id for error in errors], ["hidp.E011"])
        self.assertIn("email_change_cancel", errors[0].hint)

    def test_placeholder_missing(self):
        frontend_urls = VALID_FRONTEND_URLS | {"password_reset": "/reset/{token}/"}
        with self.settings(HIDP_FRONTEND_URLS=frontend_urls):
            errors = checks.check_api_frontend_urls()
        self.assertEqual([error.id for error in errors], ["hidp.E012"])
        self.assertIn("{uidb64}", errors[0].hint)

    def test_unknown_placeholder(self):
        # Formatting this template would raise a KeyError when the email is sent.
        frontend_urls = VALID_FRONTEND_URLS | {"set_password": "/{language}/set/"}
        with self.settings(HIDP_FRONTEND_URLS=frontend_urls):
            self.assertEqual(self._check_ids(), ["hidp.E013"])

    def test_malformed_template(self):
        frontend_urls = VALID_FRONTEND_URLS | {"email_verification": "/verify/{token/"}
        with self.settings(HIDP_FRONTEND_URLS=frontend_urls):
            self.assertEqual(self._check_ids(), ["hidp.E013"])

    def test_template_not_a_string(self):
        frontend_urls = VALID_FRONTEND_URLS | {"email_change_cancel": None}
        with self.settings(HIDP_FRONTEND_URLS=frontend_urls):
            self.assertEqual(self._check_ids(), ["hidp.E013"])

    def test_every_invalid_key_is_reported(self):
        frontend_urls = VALID_FRONTEND_URLS | {
            "email_verification": "/verify/",
            "email_change_confirm": "/change-email/",
        }
        with self.settings(HIDP_FRONTEND_URLS=frontend_urls):
            self.assertEqual(self._check_ids(), ["hidp.E012", "hidp.E012"])


@override_settings(INSTALLED_APPS=["hidp.api"])
class TestUserSerializerCheck(TestCase):
    """HIDP_API_USER_SERIALIZER must name a subclass of UserSerializer."""

    def _check_ids(self):
        return [error.id for error in checks.check_api_user_serializer()]

    def test_setting_absent(self):
        self.assertEqual(self._check_ids(), [])

    @override_settings(HIDP_API_USER_SERIALIZER="hidp.api.serializers.UserSerializer")
    def test_user_serializer(self):
        self.assertEqual(self._check_ids(), [])

    @override_settings(HIDP_API_USER_SERIALIZER="tests.does.not.Exist")
    def test_not_importable(self):
        self.assertEqual(self._check_ids(), ["hidp.E014"])

    @override_settings(HIDP_API_USER_SERIALIZER="hidp.api.serializers.LoginSerializer")
    def test_not_a_user_serializer(self):
        self.assertEqual(self._check_ids(), ["hidp.E014"])
