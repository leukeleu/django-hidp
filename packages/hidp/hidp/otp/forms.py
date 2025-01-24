from django_otp.forms import OTPTokenForm as DjangoOTPTokenForm


class OTPTokenForm(DjangoOTPTokenForm):
    otp_challenge = None  # don't require OTP challenge for OTP token form
