# Registration

HIdP includes an optional custom user registration route that enables users to directly create new accounts. Users can register using a standard email and password combination. Additionally, if the `oidc_provider` extra is installed, HIdP allows users to register via an OpenID Connect (OIDC) client.

**Features**

User registration is managed by the `RegistrationView` at the `signup/` route.

:::{note}
The availability of the `signup/` route can be controlled using the `REGISTRATION_ENABLED` setting. If not defined, it defaults to `True`. In a future version of HIdP, registration will be disabled if `REGISTRATION_ENABLED` is not defined. It is recommended to explicitly set `REGISTRATION_ENABLED` to `True` or `False` in your settings.
:::

## Email and password registration

New user creation is handled by the `UserCreationForm`, which builds upon Django's built-in `BaseUserCreationForm` with a few modifications.

- The option to create an account with an unusable password is removed, ensuring all users set a valid password.

- The unique constraint on the email field is removed to prevent user enumeration attacks, allowing the form to submit even if the email is already registered.

- A `TermsOfServiceMixin` is included to ensure users agree to your Terms of Service before they can create an account. See [Terms of Service](project:terms-of-service.md) for instructions on how to disable this.

The password is validated using the validators configured in `settings.AUTH_PASSWORD_VALIDATORS`. See [Password Validators](project:password-validators.md) on custom HIdP password validators.

### Verification email

HIdP introduces an extra step in the account registration flow by sending a verification email. If the `UserCreationForm` is valid and a new user is created, the user will receive a verification email with a link to confirm their account and will be redirected to the `EmailVerificationRequiredView` informing them that email verification is required. After confirmation, the `email_verified` field is updated with the `datetime` of confirmation.

:::{note}
The verification link contains a signed hash of the user's email, with a timestamp, and is valid for one hour.
:::

If the form contains an email that is already registered, a different email is sent to notify the user that an attempt was made to create an account using their email address.

See [verification email templates](project:templates.md#accounts-verification-email) on which templates are used.

## Registration via OpenID Connect

HIdP also adds the option to directly register via an OpenID Connect client. For each registered client, a sign-up option is added to the registration view. See [Configure OIDC Clients](project:configure-oidc-clients.md) on how to set up such a client.

In contrast to the email and password registration flow, when a user tries to sign up with an already registered email, they will either be logged in (if their email is verified) or they will be redirected to the `EmailVerificationRequiredView` if the email hasn't been verified.
