# Configuration

`REGISTRATION_ENABLED`

Enable registration of new users from within HIdP. Default is `False`. This controls whether the HIdP registration form is shown to unauthenticated users. New users can still be created by an admin
user in the Django or Wagtail admin interface.

`OTP_TOTP_ISSUER`

The issuer name to use in the TOTP URI. When not set, it will default to the domain
part of the user's email address (without TLD), i.e. `example` if your emailaddress is `username@example.org`. For more information see the [django-otp docs](https://django-otp-official.readthedocs.io/en/stable/overview.html#std-setting-OTP_TOTP_ISSUER).

