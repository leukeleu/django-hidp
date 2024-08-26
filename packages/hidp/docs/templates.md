# Templates

HIdP provides a set of basic templates that you’ll likely want to customize
to match your application's look and feel.

These templates are located in the `templates/hidp` directory.
To override them, create a file in your application's template directory
with the same path as the templates you are trying to override.

For more information on overriding templates, visit
[Django's documentation](https://docs.djangoproject.com/en/stable/howto/overriding-templates/).

The templates available are:
:::{contents}
:depth: 5
:local:
:::

## base.html

This is the base template that every template in HIdP extends. It includes the basic
HTML boilerplate for each page. Override this template to load custom CSS, scripts,
and set up a base layout.

This template defines two blocks that all other templates depend on:
- `title` - inside the HTML title tag
- `body` - inside the HTML body tag

## **accounts**

All templates related to the authentication, registration, recovery and verification
can be found in this directory and subdirectories: `templates/hidp/accounts`.

### login.html

Rendered by the `LoginView`.

This template gets passed the following context variables:
- `form` - The login form.
- `oidc_login_providers` - List of dicts of configured OIDC providers with the following
information per provider:
  - `provider` - Registered OIDC provider.
  - `url` - Authentication URL for the OIDC provider.
- `self.redirect_field_name` (i.e. `next`) - The URL to redirect to after login (if
present in the request).
- `site` - The current site instance (`RequestSite` if `django.contrib.sites` is
not installed).
- `site_name` - The name of the current site (host name if `RequestSite` is used)
- `messages` - messages from `django.contrib.messages`.
- `register_url` - URL to the sign up page, with a next param if `redirect_url` is
available.
- Any additional data present is `self.extra_context`.

### logout_confirm.html

Rendered by the `RPInitiatedLogoutView`.

This template gets passed the following context variables:
- `application` - An [`Application`](https://django-oauth-toolkit.readthedocs.io/en/latest/models.html#oauth2_provider.models.Application) object.

:::{note}
One extra variable, named error will also be available if an Oauth2 exception occurs.
This variable is a dict with `error` and `description`.
:::

### register.html

Rendered by the `RegistrationView`.

This template gets passed the following context variables:
- `form` - The registration form.
- `login_url` - URL to the login page, with a next param if `redirect_url` is available.

### tos.html

Rendered by the `TermsOfServiceView`.

:::{important}
This template serves as an example and is not suited for use in production. Please
override this template to provide your own Terms of Service or disable the
`agreed_to_tos` field by overriding the `UserCreationForm`.
:::

### **recovery**

All templates related to password recovery can be found
in `templates/hidp/accounts/recovery`.

#### password_reset_request.html

Rendered by the `PasswordResetRequestView`.

This template gets passed the following context variables:
- `form` - The password reset request form, where users need to fill in their
email address.

#### password_reset_email_sent.html

Rendered by the `PasswordResetEmailSentView`.

#### password_reset.html

Rendered by the `PasswordResetView`, which is a subclass of Django's `PasswordResetConfirmView`.

This template gets passed the following context variables:
- `form` - The password reset form.
- `validlink` - boolean that indicates the validity of the used token.

#### password_reset_complete.html

Rendered by the `PasswordResetCompleteView`.

This template gets passed the following context variables:
- `login_url` - URL to the login page, with a next param if `redirect_url` is available.

#### **email**

Templates for to password recovery emails can be found
in `templates/hidp/accounts/recovery/email`.

##### password_reset_email_body.txt

Sent by the `PasswordResetRequestView`.

This template gets passed the following context variable:
- `password_reset_url` - URL to `PasswordResetView`.

##### password_reset_email_subject.txt

The subject of the email is set with this template: `password_reset_subject.txt`.

### **verification**

Templates for the verification emails can be found
in `templates/hidp/accounts/verification`.

#### email_verification_required.html

Rendered by the `EmailVerificationRequiredView`.

This template gets passed the following context variables:
- `validlink` - boolean that indicates the validity of the used token.

#### verify_email.html

Rendered by the `EmailVerificationView`.

This template gets passed the following context variables:
- `form` - The email verification form.
- `validlink` - boolean that indicates the validity of the used token.

#### email_verification_complete.html

Rendered by the `EmailVerificationCompleteView`.

This template gets passed the following context variables:
- `login_url` - URL to the login page, with a next param if `redirect_url` is available.

#### **email**

Templates for to verification emails can be found email
in `templates/hidp/accounts/verification/email`.

##### verification_email_body.txt

Sent by the `RegistrationView`.

This template gets passed the following context variable:
- `verification_url` - URL to `EmailVerificationView`.

##### verification_email_subject.txt

The subject of the email is set with this template: `verification_subject.txt`.

##### account_exists_email_body.txt

Sent by the `RegistrationView` if an account already exists with that email address.

This template gets passed the following context variable:
- `password_reset_url` - URL to `PasswordResetRequestView`.

##### account_exists_email_subject.txt

The subject of the email is set with this template: `account_exists_subject.txt`.

## **federated**

All templates related to the OIDC authentication and registration can be found
in: `templates/hidp/federated`.

### account_link.html

Rendered by the `OIDCAccountLinkView`.

This template gets passed the following context variables:
- `form` - The account link form.
- `provider` - The OIDC provider that the user is linking their account to.

### registration.html

Rendered by the `OIDCRegistrationView`.

This template gets passed the following context variables:
- `form` - The OIDC registration form.
