import string

from django.core.exceptions import ValidationError
from django.test import SimpleTestCase

from hidp.accounts.password_validation import (
    DigitValidator,
    LowercaseValidator,
    SymbolValidator,
    UppercaseValidator,
)


class TestPasswordValidation(SimpleTestCase):
    def test_digit_validator(self):
        validator = DigitValidator()

        self.assertEqual(
            validator.get_help_text(),
            "Your password must contain at least one digit (0-9).",
        )

        with self.subTest("Valid password"):
            validator.validate("P@ssw0rd!")

        with (
            self.subTest("Invalid password"),
            self.assertRaises(ValidationError) as cm,
        ):
            validator.validate("Password!")
        self.assertEqual(cm.exception.code, "password_no_digit")
        self.assertEqual(
            cm.exception.message, "This password does not contain any digits (0-9)."
        )

    def test_uppercase_validator(self):
        validator = UppercaseValidator()

        self.assertEqual(
            validator.get_help_text(),
            "Your password must contain at least one uppercase character (A-Z).",
        )

        with self.subTest("Valid password"):
            validator.validate("P@ssw0rd!")

        with (
            self.subTest("Invalid password"),
            self.assertRaises(ValidationError) as cm,
        ):
            validator.validate("p@ssw0rd!")
        self.assertEqual(cm.exception.code, "password_no_upper")
        self.assertEqual(
            cm.exception.message,
            "This password does not contain any uppercase characters (A-Z).",
        )

    def test_lowercase_validator(self):
        validator = LowercaseValidator()

        self.assertEqual(
            validator.get_help_text(),
            "Your password must contain at least one lowercase character (a-z).",
        )

        with self.subTest("Valid password"):
            validator.validate("P@ssw0rd!")

        with (
            self.subTest("Invalid password"),
            self.assertRaises(ValidationError) as cm,
        ):
            validator.validate("P@SSW0RD!")
        self.assertEqual(cm.exception.code, "password_no_lower")
        self.assertEqual(
            cm.exception.message,
            "This password does not contain any lowercase characters (a-z).",
        )

    def test_symbol_validator(self):
        validator = SymbolValidator()
        punctuation = string.punctuation

        self.assertEqual(
            validator.get_help_text(),
            (
                f"Your password must contain at least one"
                f" special character ({punctuation})."
            ),
        )

        with self.subTest("Valid password"):
            validator.validate("P@ssw0rd!")

        with (
            self.subTest("Invalid password"),
            self.assertRaises(ValidationError) as cm,
        ):
            validator.validate("Password1")
        self.assertEqual(cm.exception.code, "password_no_symbol")
        self.assertEqual(
            cm.exception.message,
            f"This password does not contain any special characters ({punctuation}).",
        )
