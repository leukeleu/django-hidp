from base64 import b32encode
from http import HTTPStatus

import segno

from django_otp.plugins.otp_static.models import StaticDevice
from django_otp.plugins.otp_totp.models import TOTPDevice
from drf_spectacular.utils import extend_schema, extend_schema_view
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response

from django.db import transaction
from django.http import Http404
from django.utils.decorators import method_decorator
from django.utils.translation import gettext_lazy as _

from hidp.otp import flows
from hidp.otp.decorators import otp_exempt
from hidp.otp.devices import (
    get_device_for_user,
    get_or_create_devices,
    reset_static_tokens,
)
from hidp.otp.exceptions import NoOtpDeviceError
from hidp.otp.mailers import (
    OTPConfiguredMailer,
    OTPDisabledMailer,
    RecoveryCodesRegeneratedMailer,
    RecoveryCodeUsedMailer,
)

from ..rate_limit.decorators import rate_limit_default
from .auth_state import auth_state_response
from .otp_serializers import (
    OTPSetupDetailsSerializer,
    OTPSetupSerializer,
    OTPStatusSerializer,
    OTPTokenSerializer,
    RecoveryCodeSerializer,
    RecoveryCodesSerializer,
)
from .views import (
    AUTH_STATE_RESPONSES,
    FORBIDDEN_RESPONSE,
    NO_CONTENT_OR_FORBIDDEN,
    BaseView,
    permission_denied,
)


def _recovery_codes(device):
    return list(device.token_set.values_list("token", flat=True))


def _confirmed_static_device(user):
    return StaticDevice.objects.devices_for_user(user, confirmed=True).first()


class OTPView(BaseView):
    permission_classes = [IsAuthenticated]
    # A wrong code must still count towards the lockout of the device.
    keep_writes_on_invalid_input = True

    def send_mail(self, mailer_class):
        mailer_class(
            self.request.user,
            base_url=self.base_url,
            otp_management_url=self.frontend_url("otp_management"),
        ).send()

    def ensure_device_configured(self, device_class):
        try:
            get_device_for_user(self.request.user, device_class)
        except NoOtpDeviceError:
            raise permission_denied(
                _("Two-factor authentication is not configured."), "otp_not_configured"
            ) from None


@extend_schema_view(get=extend_schema(responses=OTPStatusSerializer))
class OTPStatusView(OTPView):
    """Whether two-factor authentication is configured, and the codes left."""

    def get(self, request, *args, **kwargs):  # noqa: PLR6301 (no-self-use)
        configured = TOTPDevice.objects.devices_for_user(
            request.user, confirmed=True
        ).exists()
        static_device = _confirmed_static_device(request.user)
        return Response(
            OTPStatusSerializer(
                {
                    "configured": configured,
                    "recovery_codes_remaining": (
                        static_device.token_set.count() if static_device else None
                    ),
                }
            ).data
        )


@method_decorator(otp_exempt, name="dispatch")
@method_decorator(rate_limit_default, name="dispatch")
@extend_schema_view(
    get=extend_schema(
        responses={
            HTTPStatus.OK: OTPSetupDetailsSerializer,
            HTTPStatus.FORBIDDEN: FORBIDDEN_RESPONSE,
        }
    ),
    post=extend_schema(responses=AUTH_STATE_RESPONSES),
)
class OTPSetupView(OTPView):
    """
    Set up two-factor authentication with an authenticator app.

    GET returns the same unconfirmed device until a POST with a valid code confirms
    it, which also verifies the session.
    """

    serializer_class = OTPSetupSerializer
    configured_mailer = OTPConfiguredMailer

    def initial(self, request, *args, **kwargs):
        super().initial(request, *args, **kwargs)
        if TOTPDevice.objects.devices_for_user(request.user, confirmed=True).exists():
            raise permission_denied(
                _("Two-factor authentication is already configured."),
                "otp_already_configured",
            )
        if flows.setup_requires_verification(request.user):
            raise permission_denied(
                _("Verify this session with a recovery code first."),
                "otp_verification_required",
            )
        self.device, self.backup_device = get_or_create_devices(request.user)

    def get_serializer_context(self):
        return super().get_serializer_context() | {
            "device": self.device,
            "backup_device": self.backup_device,
        }

    def get(self, request, *args, **kwargs):
        return Response(
            OTPSetupDetailsSerializer(
                {
                    "secret": b32encode(self.device.bin_key).decode(),
                    "config_url": self.device.config_url,
                    "qr_code": segno.make(self.device.config_url).svg_data_uri(
                        border=0
                    ),
                    "recovery_codes": _recovery_codes(self.backup_device),
                }
            ).data
        )

    def post(self, request, *args, **kwargs):
        flows.confirm_setup(request, self.validated_serializer().form)
        self.send_mail(self.configured_mailer)
        return auth_state_response(request)


@method_decorator(otp_exempt, name="dispatch")
@method_decorator(rate_limit_default, name="dispatch")
@extend_schema_view(post=extend_schema(responses=AUTH_STATE_RESPONSES))
class OTPVerifyView(OTPView):
    """Verify the session with a code from the authenticator app."""

    serializer_class = OTPTokenSerializer
    device_class = TOTPDevice
    recovery_code_used_mailer = None
    # Codes from the app and recovery codes share one budget.
    rate_limit_group = "hidp.otp.verify"

    def post(self, request, *args, **kwargs):
        self.ensure_device_configured(self.device_class)
        self.validated_serializer()
        flows.verify(request)
        if self.recovery_code_used_mailer is not None:
            self.send_mail(self.recovery_code_used_mailer)
        return auth_state_response(request)


class OTPVerifyRecoveryCodeView(OTPVerifyView):
    """Verify the session with a recovery code, which is used up."""

    serializer_class = RecoveryCodeSerializer
    device_class = StaticDevice
    recovery_code_used_mailer = RecoveryCodeUsedMailer


@method_decorator(rate_limit_default, name="dispatch")
@extend_schema_view(post=extend_schema(responses=NO_CONTENT_OR_FORBIDDEN))
class OTPDisableView(OTPView):
    """Disable two-factor authentication, confirmed with a code from the app."""

    serializer_class = OTPTokenSerializer
    device_class = TOTPDevice
    disabled_mailer = OTPDisabledMailer
    rate_limit_group = "hidp.otp.disable"

    def post(self, request, *args, **kwargs):
        self.ensure_device_configured(self.device_class)
        self.validated_serializer()
        with transaction.atomic():
            flows.disable(request.user)
            self.send_mail(self.disabled_mailer)
        return Response(status=HTTPStatus.NO_CONTENT)


class OTPDisableRecoveryCodeView(OTPDisableView):
    """Disable two-factor authentication, confirmed with a recovery code."""

    serializer_class = RecoveryCodeSerializer
    device_class = StaticDevice


@method_decorator(rate_limit_default, name="dispatch")
@extend_schema_view(
    get=extend_schema(responses=RecoveryCodesSerializer),
    post=extend_schema(request=None, responses=RecoveryCodesSerializer),
)
class RecoveryCodesView(OTPView):
    """The recovery codes of the user. POST replaces them with new ones."""

    regenerated_mailer = RecoveryCodesRegeneratedMailer

    def get_object(self):
        device = _confirmed_static_device(self.request.user)
        if device is None:
            raise Http404
        return device

    def get(self, request, *args, **kwargs):
        codes = _recovery_codes(self.get_object())
        return Response(RecoveryCodesSerializer({"recovery_codes": codes}).data)

    def post(self, request, *args, **kwargs):
        device = self.get_object()
        reset_static_tokens(device)
        self.send_mail(self.regenerated_mailer)
        codes = _recovery_codes(device)
        return Response(RecoveryCodesSerializer({"recovery_codes": codes}).data)
