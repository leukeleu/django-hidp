import django_otp
import segno

from django_otp.plugins.otp_static.models import StaticDevice
from django_otp.plugins.otp_totp.models import TOTPDevice

from django.conf import settings
from django.contrib.auth.decorators import login_required
from django.contrib.auth.views import RedirectURLMixin
from django.db import transaction
from django.forms import Form
from django.http import HttpResponseRedirect
from django.shortcuts import get_object_or_404
from django.urls import reverse, reverse_lazy
from django.utils.decorators import method_decorator
from django.views.generic import DetailView, FormView, TemplateView

from hidp.csp.decorators import hidp_csp_protection
from hidp.otp.devices import (
    STATIC_DEVICE_NAME,
    TOTP_DEVICE_NAME,
    get_or_create_devices,
    reset_static_tokens,
)
from hidp.otp.forms import OTPSetupForm, VerifyStaticTokenForm, VerifyTOTPForm
from hidp.rate_limit.decorators import rate_limit_default

from .decorators import otp_exempt
from .mailers import (
    OTPConfiguredMailer,
    OTPDisabledMailer,
    RecoveryCodesRegeneratedMailer,
    RecoveryCodeUsedMailer,
)


@method_decorator(hidp_csp_protection, name="dispatch")
@method_decorator(login_required, name="dispatch")
class OTPOverviewView(TemplateView):
    template_name = "hidp/otp/overview.html"

    def get_context_data(self, **kwargs):
        context = {
            "totp_devices": TOTPDevice.objects.devices_for_user(
                self.request.user, confirmed=True
            ),
            "static_devices": StaticDevice.objects.devices_for_user(
                self.request.user, confirmed=True
            ),
            "TOTP_DEVICE_NAME": TOTP_DEVICE_NAME,
            "STATIC_DEVICE_NAME": STATIC_DEVICE_NAME,
            "back_url": reverse("hidp_account_management:manage_account"),
        }
        return super().get_context_data() | context | kwargs


@method_decorator(hidp_csp_protection, name="dispatch")
@method_decorator(rate_limit_default, name="dispatch")
@method_decorator(login_required, name="dispatch")
class OTPDisableView(FormView):
    """
    View to disable OTP for a user.

    This view will delete all OTP devices for a user, effectively disabling OTP for
    that user. Disabling requires the user to be logged in and to provide a valid OTP
    token.
    """

    template_name = "hidp/otp/disable.html"
    form_class = VerifyTOTPForm
    success_url = reverse_lazy("hidp_otp_management:manage")

    def get_context_data(self, **kwargs):
        context = {
            "back_url": reverse("hidp_otp_management:manage"),
        }
        return super().get_context_data() | context | kwargs

    def get_form_kwargs(self):
        context = {
            "user": self.request.user,
        }
        return super().get_form_kwargs() | context

    @transaction.atomic
    def form_valid(self, form):
        for device in django_otp.devices_for_user(self.request.user):
            device.delete()

        self.send_mail()

        return super().form_valid(form)

    def send_mail(self):
        base_url = self.request.build_absolute_uri("/")

        OTPDisabledMailer(self.request.user, base_url=base_url).send()


class OTPDisableViewRecoveryCode(OTPDisableView):
    """
    View to disable OTP for a user using a recovery code.

    This view will delete all OTP devices for a user, effectively disabling OTP for
    that user. Disabling requires the user to be logged in and to provide a valid
    recovery code.
    """

    template_name = "hidp/otp/disable_recovery_code.html"
    form_class = VerifyStaticTokenForm


@method_decorator(hidp_csp_protection, name="dispatch")
@method_decorator(login_required, name="dispatch")
class OTPRecoveryCodes(DetailView, FormView):
    """
    View for managing recovery codes.

    This view allows the user to reset their recovery codes.
    """

    template_name = "hidp/otp/recovery_codes.html"
    context_object_name = "device"
    form_class = Form
    success_url = reverse_lazy("hidp_otp_management:recovery-codes")

    def get_object(self, queryset=None):
        return get_object_or_404(
            StaticDevice.objects.devices_for_user(self.request.user)
        )

    def get_context_data(self, **kwargs):
        context = {
            "back_url": reverse("hidp_otp_management:manage"),
            "recovery_codes": "\n".join(
                self.object.token_set.values_list("token", flat=True)
            ),
        }
        return super().get_context_data() | context | kwargs

    def form_valid(self, form):
        reset_static_tokens(self.get_object())

        self.send_mail()

        return super().form_valid(form)

    def send_mail(self):
        base_url = self.request.build_absolute_uri("/")

        RecoveryCodesRegeneratedMailer(self.request.user, base_url=base_url).send()


@method_decorator(hidp_csp_protection, name="dispatch")
@method_decorator(rate_limit_default, name="dispatch")
@method_decorator(login_required, name="dispatch")
@method_decorator(otp_exempt, name="dispatch")
class OTPSetupDeviceView(RedirectURLMixin, FormView):
    """
    View for setting up a new OTP device.

    This view will create a new TOTP and Static device in unconfirmed state for the user
    if they don't already have them. The user must verify the TOTP device by entering a
    valid token and declare that they have saved the recovery codes before the devices
    are confirmed.
    """

    form_class = OTPSetupForm
    next_page = reverse_lazy("hidp_otp_management:setup-device-done")
    template_name = "hidp/otp/setup_device.html"

    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.device = None
        self.user = None

    def dispatch(self, request, *args, **kwargs):
        self.user = request.user

        # If the user already has a confirmed TOTP device, redirect to the manage page
        if TOTPDevice.objects.devices_for_user(self.user, confirmed=True).exists():
            return HttpResponseRedirect(self.get_success_url())

        self.device, self.backup_device = get_or_create_devices(self.user)

        return super().dispatch(request, *args, **kwargs)

    def get_form_kwargs(self):
        kwargs = super().get_form_kwargs()
        kwargs.update(
            {
                "user": self.user,
                "device": self.device,
                "backup_device": self.backup_device,
            }
        )
        return kwargs

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)

        return context | {
            "title": "Set up Two-Factor Authentication",
            "device": self.device,
            "backup_device": self.backup_device,
            "qrcode": segno.make(self.device.config_url).svg_data_uri(border=0),
            "config_url": self.device.config_url,
            "recovery_codes": "\n".join(
                self.backup_device.token_set.values_list("token", flat=True)
            ),
            "back_url": reverse("hidp_otp_management:manage"),
        }

    def form_valid(self, form):
        form.save()
        django_otp.login(self.request, self.device)

        self.send_mail()

        return super().form_valid(form)

    def send_mail(self):
        base_url = self.request.build_absolute_uri("/")

        OTPConfiguredMailer(self.user, base_url=base_url).send()


@method_decorator(hidp_csp_protection, name="dispatch")
@method_decorator(rate_limit_default, name="dispatch")
@method_decorator(login_required, name="dispatch")
class OTPSetupDeviceDoneView(TemplateView):
    template_name = "hidp/otp/setup_device_done.html"

    def get_context_data(self, **kwargs):
        context = {
            "back_url": reverse("hidp_otp_management:manage"),
        }
        return super().get_context_data() | context | kwargs


@method_decorator(hidp_csp_protection, name="dispatch")
@method_decorator(rate_limit_default, name="dispatch")
@method_decorator(login_required, name="dispatch")
@method_decorator(otp_exempt, name="dispatch")
class VerifyOTPBase(RedirectURLMixin, FormView):
    next_page = settings.LOGIN_REDIRECT_URL

    def get_form_kwargs(self):
        kwargs = super().get_form_kwargs()
        kwargs["user"] = self.request.user
        return kwargs

    def form_valid(self, form):
        # Persist the OTP device in the session
        django_otp.login(self.request, self.request.user.otp_device)
        return super().form_valid(form)


class VerifyTOTPView(VerifyOTPBase):
    template_name = "hidp/otp/verify.html"
    form_class = VerifyTOTPForm


class VerifyRecoveryCodeView(VerifyOTPBase):
    template_name = "hidp/otp/verify_recovery_code.html"
    form_class = VerifyStaticTokenForm

    def form_valid(self, form):
        result = super().form_valid(form)

        self.send_mail()

        return result

    def send_mail(self):
        """Notify the user that a recovery code was used."""
        base_url = self.request.build_absolute_uri("/")
        RecoveryCodeUsedMailer(self.request.user, base_url=base_url).send()
