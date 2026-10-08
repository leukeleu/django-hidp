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
    # Django OAuth Toolkit reloads its settings on change and needs a dict.
    OAUTH2_PROVIDER={},
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

    @override_settings(ROOT_URLCONF="tests.unit_tests.test_config.headless_urls")
    def test_urls_not_needed_when_headless(self):
        self.assertEqual(checks.check_login_url(), [])

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


@override_settings(INSTALLED_APPS=["hidp.api"])
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

    def test_invalid_template(self):
        for key, url_template in [
            # Formatting would raise a KeyError when the email is sent.
            ("set_password", "/{language}/set/"),
            ("set_password", "/{}/set/"),
            ("email_verification", "/verify/{token/"),
            ("email_verification", "/verify/{token:{x}}/"),
            ("email_verification", "/verify/{token!r}/"),
            ("email_change_cancel", None),
        ]:
            frontend_urls = VALID_FRONTEND_URLS | {key: url_template}
            with (
                self.subTest(url_template=url_template),
                self.settings(HIDP_FRONTEND_URLS=frontend_urls),
            ):
                self.assertEqual(self._check_ids(), ["hidp.E013"])

    def test_every_invalid_key_is_reported(self):
        frontend_urls = VALID_FRONTEND_URLS | {
            "email_verification": "/verify/",
            "email_change_confirm": "/change-email/",
        }
        with self.settings(HIDP_FRONTEND_URLS=frontend_urls):
            self.assertEqual(self._check_ids(), ["hidp.E012", "hidp.E012"])


class TestOTPFrontendUrlsCheck(TestCase):
    """The OTP keys of HIDP_FRONTEND_URLS are checked when hidp.otp is installed."""

    def _check_ids(self, frontend_urls, installed_apps=("hidp.api", "hidp.otp")):
        with self.settings(
            INSTALLED_APPS=list(installed_apps), HIDP_FRONTEND_URLS=frontend_urls
        ):
            return [error.id for error in checks.check_api_frontend_urls()]

    def test_otp_management_required_with_otp(self):
        self.assertEqual(self._check_ids(VALID_FRONTEND_URLS), ["hidp.E011"])

    def test_otp_management_not_required_without_otp(self):
        self.assertEqual(
            self._check_ids(VALID_FRONTEND_URLS, installed_apps=["hidp.api"]), []
        )

    def test_optional_redirect_urls(self):
        frontend_urls = VALID_FRONTEND_URLS | {
            "otp_management": "/otp/",
            "otp_verify": "/otp/verify/",
            "otp_setup": "/otp/setup/",
        }
        self.assertEqual(self._check_ids(frontend_urls), [])

    def test_optional_redirect_url_is_validated(self):
        frontend_urls = VALID_FRONTEND_URLS | {
            "otp_management": "/otp/",
            "otp_verify": "/otp/verify/{token}/",
        }
        self.assertEqual(self._check_ids(frontend_urls), ["hidp.E013"])


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


class TestOAuth2ProviderRegistrationUrlCheck(TestCase):
    """prompt=create must be able to redirect to a registration page."""

    def test_valid(self):
        self.assertEqual(checks.check_oauth2_provider_registration_url(), [])

    @override_settings(
        OAUTH2_PROVIDER=settings.OAUTH2_PROVIDER
        | {"OIDC_RP_INITIATED_REGISTRATION_URL": "/signup"}
    )
    def test_frontend_path(self):
        self.assertEqual(checks.check_oauth2_provider_registration_url(), [])

    @override_settings(ROOT_URLCONF="tests.unit_tests.test_config.headless_urls")
    def test_registration_url_not_mounted(self):
        self.assertEqual(checks.check_oauth2_provider_registration_url(), [checks.E016])

    @override_settings(
        ROOT_URLCONF="tests.unit_tests.test_config.headless_urls",
        OAUTH2_PROVIDER=settings.OAUTH2_PROVIDER
        | {"OIDC_RP_INITIATED_REGISTRATION_ENABLED": False},
    )
    def test_registration_disabled(self):
        self.assertEqual(checks.check_oauth2_provider_registration_url(), [])


@override_settings(ROOT_URLCONF="hidp.config.urls")
class TestApiPathPrefixesCheck(TestCase):
    """HIDP_API_PATH_PREFIXES must not cover pages that browsers navigate to."""

    def test_not_set(self):
        self.assertEqual(checks.check_api_path_prefixes(), [])

    @override_settings(HIDP_API_PATH_PREFIXES=["/api/"])
    def test_api_paths(self):
        self.assertEqual(checks.check_api_path_prefixes(), [])

    @override_settings(HIDP_API_PATH_PREFIXES="/api/")
    def test_not_a_list(self):
        self.assertEqual(checks.check_api_path_prefixes(), [checks.E018])

    @override_settings(HIDP_API_PATH_PREFIXES=["api/"])
    def test_relative_path(self):
        self.assertEqual(checks.check_api_path_prefixes(), [checks.E018])

    @override_settings(HIDP_API_PATH_PREFIXES=["/"])
    def test_covers_browser_pages(self):
        self.assertEqual(
            [error.id for error in checks.check_api_path_prefixes()],
            ["hidp.W003"] * 4,
        )
