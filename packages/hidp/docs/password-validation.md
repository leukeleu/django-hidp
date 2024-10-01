# Password Validators

HIdP comes with a set of custom password validators to ensure that passwords meet certain complexity requirements.
These validators enforce rules such as requiring digits, uppercase and lowercase characters, and special symbols;
enhancing security by enforcing password diversity.

Each validator is independent, enable any combination (or none) to suite your password policy requirements.

## Available validators

These password validators are available:

- **DigitValidator**: Requires a password with at least one digit (0-9).
- **UppercaseValidator**: Requires a password with at least one uppercase letter (A-Z).
- **LowercaseValidator**: Requires a password with at least one lowercase letter (a-z).
- **SymbolValidator**: Requires a password with at least one special character from the set ``!"#$%&'()*+,-./:;<=>?@[\]^_`{|}~``.

## Configuring Password Validators

To use these custom password validators, add them to the `AUTH_PASSWORD_VALIDATORS` setting in your Django project
(among the other validators you may have configured):

```python
AUTH_PASSWORD_VALIDATORS = [
    {
        "NAME": "hidp.accounts.password_validation.DigitValidator",
    },
    {
        "NAME": "hidp.accounts.password_validation.UppercaseValidator",
    },
    {
        "NAME": "hidp.accounts.password_validation.LowercaseValidator",
    },
    {
        "NAME": "hidp.accounts.password_validation.SymbolValidator",
    }
]
```

Adding these validators ensures that any passwords set or updated will have to meet these required criteria.

For more information on configuring password validation in Django, refer to
[Django's documentation](https://docs.djangoproject.com/en/stable/topics/auth/passwords/#password-validation).
