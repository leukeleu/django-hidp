import re
import string

from django.core.exceptions import ValidationError
from django.utils.text import format_lazy
from django.utils.translation import gettext_lazy as _


class RegexValidator:
    regex = NotImplemented
    message = NotImplemented
    code = NotImplemented
    help_text = NotImplemented

    def validate(self, password, user=None):
        if not re.search(self.regex, password):
            raise ValidationError(self.message, code=self.code)

    def get_help_text(self):
        return self.help_text


class DigitValidator(RegexValidator):
    regex = r"[0-9]"
    message = _("This password does not contain any digits (0-9).")
    code = "password_no_digit"
    help_text = _("Your password must contain at least one digit (0-9).")


class UppercaseValidator(RegexValidator):
    regex = r"[A-Z]"
    message = _("This password does not contain any uppercase characters (A-Z).")
    code = "password_no_upper"
    help_text = _("Your password must contain at least one uppercase character (A-Z).")


class LowercaseValidator(RegexValidator):
    regex = r"[a-z]"
    message = _("This password does not contain any lowercase characters (a-z).")
    code = "password_no_lower"
    help_text = _("Your password must contain at least one lowercase character (a-z).")


class SymbolValidator(RegexValidator):
    regex = "|".join(re.escape(c) for c in string.punctuation)
    message = format_lazy(
        _("This password does not contain any special characters ({})."),
        string.punctuation,
    )
    code = "password_no_symbol"
    help_text = format_lazy(
        _("Your password must contain at least one special character ({})."),
        string.punctuation,
    )
