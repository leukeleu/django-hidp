# Templates

HIdP provides a set of basic templates that you’ll likely want to customize
to match your application's look and feel.

These templates are located in the `templates/hidp` directory.
To override them, create a file in your application's template directory
with the same path as the templates you are trying to override.

Forms are rendered using Django's built-in form rendering system, and each
form is assigned their own template. In order to override the form templates,
using a template from your project's template directory some additional
configuration is required.

```python
# settings.py
INSTALLED_APPS = [
  ...,
  "django.forms",
  ...,
]

FORM_RENDERER = "django.forms.renderers.TemplatesSetting"
```

For more information on overriding templates in general, visit
[Django's documentation](https://docs.djangoproject.com/en/stable/howto/overriding-templates/).

For more information on overriding form templates, read this section in
[Django's documentation](https://docs.djangoproject.com/en/stable/topics/forms/#reusable-form-templates).

The templates available are:
:::{contents}
:depth: 3
:local:
:::

---

## Base templates

To facilitate the common use case of having a distinct layout for the pre-login and
post-login pages, HIdP provides a base template hierarchy that you can extend to
customize the layout of your application.

### base.html

This is the root base template that every template in HIdP extends. It includes the
basic HTML boilerplate for each page. Override this template to load custom CSS,
scripts, and set up a base layout.

This template defines two blocks that all other templates depend on:

`title`
: inside the HTML `title` tag.

`body`
: inside the HTML `body` tag.

`main`
: inside the `body` block, where the main application content is rendered.

This template also defines two blocks that you can extend to inject extra styles and/or
scripts:

`extra_head`
: inside the HTML head tag, after the `title` tag.

`extra_body`
: inside the HTML body tag, below the `body` block.

### base_pre_login.html

This template extends `base.html` and is used for all pre-login pages. It does not
add anything over the base template and is only provided as an extension point.

### base_post_login.html

This template extends `base.html` and is used for all post-login pages. It does not
add anything over the base template and is only provided as an extension point.

### base_form.html

This is the base template for all forms in HIdP. It extends the default Django form
template (`django/forms/div.html`) (without any modifications). Override this template
to customize the layout of HIdP forms on a global basis.

Each form is assigned a template that extends this base template (again, without any
modifications). These templates are noted in the per-page documentation below.

---

## accounts/

All templates related to the authentication, registration, recovery and verification
can be found in this directory and subdirectories: `templates/hidp/accounts`.

### login.html

Rendered by the `LoginView`.

**Base template**: `base_pre_login.html`

**Form template**: 

* `accounts/forms/authentication_form.html`
* `accounts/forms/rate_limited_authentication_form.html` (if rate limited)

**Context variables**

`form`
: The login form.

`oidc_login_providers`
: List of dicts of configured OIDC providers with the following
  information per provider:

  `provider`
  : Registered OIDC provider.

  `url`
  : Authentication URL for the OIDC provider.

`oidc_error_message`
: Error message from the OIDC Authentication flow in case
  something went wrong.

`self.redirect_field_name` (i.e. `next`)
: The URL to redirect to after login (if present in the request).

`site`
: The current site instance (`RequestSite` if `django.contrib.sites` is not installed).

`site_name`
: The name of the current site (host name if `RequestSite` is used)

`password_reset_url`
: URL to the password reset page.

`register_url`
: URL to the sign-up page, with a next param if `redirect_url` is available.

`is_rate_limited`
: Whether the view is rate limited or not; result of `request.limited`.

### logout_confirm.html

Rendered by the `RPInitiatedLogoutView` and is used to confirm the logout.

**Base template**: `base_pre_login.html`

Using the pre-login base template might sound counterintuitive, but the logout
confirmation page is shown regardless of the user's authentication status.

**Context variables**

`application`
: An [`Application`](https://django-oauth-toolkit.readthedocs.io/en/latest/models.html#oauth2_provider.models.Application) object.

`error`
: An error message if an error occurred during the logout process. This is a dict
  with `error` and `description`.

### register.html

Rendered by the `RegistrationView`.

**Base template**: `base_pre_login.html`

**Form template**: `accounts/forms/user_creation_form.html`

**Context variables**

`form`
: The registration form.

`user`
: The current user instance.

`login_url`
: URL to the login page, with a next param if `redirect_url` is available.

`next`
: URL to redirect to after successful registration.

`logout_url`
: URL to the logout page.

`logout_next_url`
: URL to same page, redirecting to login page if necessary.

`can_register`
: `False` if the user is authenticated.

### tos.html

Rendered by the `TermsOfServiceView`.

**Base template**: `base_pre_login.html`

:::{important}
This template serves as an example and is not suited for use in production. Please
override this template to provide your own Terms of Service or disable the
`agreed_to_tos` field by overriding the `UserCreationForm`.
:::

---

## accounts/management/

All templates related to account management can be found
in `templates/hidp/accounts/management`.

### manage_account.html

Rendered by the `ManageAccountView`.

**Base template**: `base_post_login.html`

**Context variables**

`user`
: The current user instance.

`logout_url`
: URL to the logout page.

`account_management_links`
: List of dicts of available account management urls with
  the following information per link:

  `text`
  : The text to show for the link.

  `url`
  : Reversed URL for the link.

### edit_account.html

Rendered by the `EditAccountView`.

**Base template**: `base_post_login.html`

**Form template**: `accounts/forms/edit_user_form.html`

**Context variables**

`form`
: A form that allows users to update their first and last name.

`cancel_url`
: Link for the cancel button.

`show_success_message`
: `True` if the account was updated successfully.

### oidc_linked_services.html

Rendered by the `OIDCLinkedServicesView`.

**Base template**: `base_post_login.html`

**Context variables**

`oidc_linked_providers`
: List of OIDC Clients that are already linked to the user's account.

`oidc_available_providers`
: List of OIDC Clients that can be linked to the user's account.

`can_unlink`
: `False` if the user has not set a password and only has one linked provider.

`set_password_url`
: URL to the set password page.

`back_url`
: Link for the cancel button.

`successfully_linked_provider`
: Name of provider that was successfully linked.

`removed_provider`
: Name of provider that was successfully removed.

`oidc_error_message`
: Error message from the OIDC Authentication flow in case something went wrong.

### password_change.html

Rendered by the `PasswordChangeView`.

Redirects to `PasswordChangeDoneView` after successfully changing the password.

**Base template**: `base_post_login.html`

**Form template**: `accounts/forms/password_change_form.html`

**Context variables**

`form`
: A form that allows users to change their password. 
  The user also needs to enter their old password to verify the user's identity.

`cancel_url`
: Link for the cancel button.

### password_change_done.html

Rendered by the `PasswordChangeDoneView`.

Shows a message letting the user know that their password has been changed.

**Base template**: `base_post_login.html`

**Context variables**

`back_url`
: Link back to the account management page.

### set_password.html

Rendered by the `SetPasswordView`.

If the user doesn't have a password set they are required to have logged in recently
in order to set a password. If the user hasn't logged in recently they need to
re-authenticate using one of the OIDC providers linked to their account.

Redirects to `SetPasswordDoneView` after successfully setting the password.

**Base template**: `base_post_login.html`

**Form template**: `accounts/forms/set_password_form.html`

**Context variables**

`form`
: A form that allows users to change their password.

`cancel_url`
: Link for the cancel button.

`must_reauthenticate`
: Boolean that indicates if the user needs to re-authenticate

`oidc_linked_providers`
: List of OIDC Clients the user can use to re-authenticate
  (only if `must_reauthenticate` is `True`).

`auth_next_url`
: URL to redirect to after re-authentication (the set password view).

### set_password_done.html

Rendered by the `SetPasswordDoneView`.

Shows a message letting the user know that their password has been set.

**Base template**: `base_post_login.html`

**Context variables**

`back_url`
: Link back to the account management page.

### email_change_request.html

Rendered by the `EmailChangeRequestView`.

**Base template**: `base_post_login.html`

**Form template**: `accounts/forms/email_change_request_form.html`

**Context variables**

`can_change_email`
: Boolean that indicates if the user can change their email address.
  A user must have a password set in order to change their email address.

`set_password_url`
: URL to the set password page.

`form`
: The email change request form, where users need to fill in a new email 
  address and password.

`cancel_url`
: Link for the cancel button.

### email_change_request_sent.html

Rendered by the `EmailChangeRequestSentView`.

**Base template**: `base_post_login.html`

### email_change_confirm.html

Rendered by the `EmailChangeConfirmView`.

**Base template**: `base_post_login.html`

**Form template**: `accounts/forms/email_change_confirm_form.html`

**Context variables**

`form`
: The email change confirm form, where users need to confirm the change.

`validlink`
: boolean that indicates the validity of the used token.

If `validlink` is `True` the following context variables are also available:

`already_confirmed_for_this_email`
: boolean that indicates if the user has already confirmed the change via the
  used token, either for the current or proposed email.

`recipient`
: String that indicates the recipient of the email. The value is either
  `'current_email'` or `'proposed_email'`.

`current_email`
: The current email address.

`proposed_email`
: The proposed new email address.

### email_change_complete.html

Rendered by the `EmailChangeCompleteView`.

**Base template**: `base_post_login.html`

**Context variables**

`current_email_confirmation_required`
: boolean that indicates that the change is confirmed through proposed email,
  but not yet through current email.

`proposed_email_confirmation_required`
: boolean that indicates that the change is confirmed through current email, 
  but not yet through proposed email.

`email_change_request_completed`
: boolean that indicates whether the entire change request is completed.

`back_url`
: Link back to the account management page.

### email_change_cancel.html

Rendered by the `EmailChangeCancelView`.

**Base template**: `base_post_login.html`

**Form template**: `accounts/forms/email_change_cancel_form.html`

**Context variables**

`validlink`
: boolean that indicates whether the request can be cancelled.

If `validlink` is `True` the following context variables are also available:

`current_email`
: The current email address.

`proposed_email`
: The proposed new email address.

`cancel_url`
: Link for the back button.

### email_change_cancel_done.html

Rendered by the `EmailChangeCancelDoneView`.

**Base template**: `base_post_login.html`

**Context variables**

`back_url`
: Link back to the account management page.

## accounts/management/email/

Templates for the password and email change emails can be found
in `templates/hidp/accounts/management/email`.

### password_changed_body.txt

Sent by the `PasswordResetView`, `SetPasswordView` and `PasswordChangeView` when a user
successfully changes their password.

**Context variables**

`password_reset_url`
: URL to the password reset page.

### password_changed_subject.txt

The subject of the email is set with this template: `password_changed_subject.txt`.

### email_change_body.txt

Sent by the `EmailChangeRequestView` to both old and new email address when a user
requests to change their email address.

**Context variables**

`confirmation_url`
: URL to `EmailChangeConfirmView`.

`user`
: The user that requested the email change

`recipient`
: String that indicates the recipient of the email. The value is either
  `'current_email'` or `'proposed_email'`.

`current_email`
: The current email address.

`proposed_email`
: The proposed new email address.

`cancel_url`
: URL to `EmailChangeCancelView`.

### email_change_subject.txt

The subject of the email is set with this template: `email_change_subject.txt`.

### email_changed_body.txt

Sent by the `EmailChangeConfirmView` to both old and new email address when a user
changed their email address.

**Context variables**

`current_email`
: The current email address.

`proposed_email`
: The proposed new email address.

### email_changed_subject.txt

The subject of the email is set with this template: `email_changed_subject.txt`.

### proposed_email_exists_body.txt

Sent by the `EmailChangeRequestView` to the new email address when a user
requests to change their email address to an email address of an existing account.

**Context variables**

`current_email`
: The current email address.

`proposed_email`
: The proposed new email address.

`cancel_url`
: URL to `EmailChangeCancelView`.

### proposed_email_change_subject.txt

The subject of the email is set with this template: `proposed_email_change_subject.txt`.

---

## accounts/recovery

All templates related to password recovery can be found
in `templates/hidp/accounts/recovery`.

### password_reset_request.html

Rendered by the `PasswordResetRequestView`.

**Base template**: `base_pre_login.html`

**Form template**: `accounts/forms/password_reset_request_form.html`

**Context variables**

`form`
: The password reset request form, where users need to fill in their email address.

### password_reset_email_sent.html

Rendered by the `PasswordResetEmailSentView`.

**Base template**: `base_pre_login.html`

### password_reset.html

Rendered by the `PasswordResetView`, which is a subclass of Django's `PasswordResetConfirmView`.

**Base template**: `base_pre_login.html`

**Form template**: `accounts/forms/password_reset_form.html`

**Context variables**

`form`
: The password reset form.

`validlink`
: boolean that indicates the validity of the used token.

### password_reset_complete.html

Rendered by the `PasswordResetCompleteView`.

**Base template**: `base_pre_login.html`

**Context variables**

`login_url`
: URL to the login page, with a next param if `redirect_url` is available.

## accounts/recovery/email/

Templates for to password recovery emails can be found
in `templates/hidp/accounts/recovery/email`.

### password_reset_body.txt

Sent by the `PasswordResetRequestView` for users that have a password set.

**Context variables**

`password_reset_url`
: URL to the password reset page.

`user`
: The user the password was changed for

### password_reset_subject.txt

The subject of the email is set with this template: `password_reset_subject.txt`.

### set_password_body.txt

Sent by the `SetPasswordView` for users that don't have a password set.

**Context variables**

`password_reset_url`
: URL to the password reset page.

### set_password_subject.txt

The subject of the email is set with this template: `set_password_subject.txt`.

---

## accounts/verification

Templates for the verification emails can be found
in `templates/hidp/accounts/verification`.

### email_verification_required.html

Rendered by the `EmailVerificationRequiredView`.

**Base template**: `base_pre_login.html`

**Context variables**

`validlink`
: boolean that indicates the validity of the used token.

### verify_email.html

Rendered by the `EmailVerificationView`.

**Base template**: `base_pre_login.html`

**Form template**: `accounts/forms/email_verification_form.html`

**Context variables**

`form`
: The email verification form.

`validlink`
: boolean that indicates the validity of the used token.

### email_verification_complete.html

Rendered by the `EmailVerificationCompleteView`.

**Base template**: `base_pre_login.html`

**Context variables**

`login_url`
: URL to the login page, with a next param if `redirect_url` is available.

## accounts/verification/email/

Templates for to verification emails can be found email
in `templates/hidp/accounts/verification/email`.

### verification_body.txt

Sent by the `RegistrationView`.

**Context variables**

`verification_url`
: URL to `EmailVerificationView`.

### verification_subject.txt

The subject of the email is set with this template: `verification_subject.txt`.

### account_exists_body.txt

Sent by the `RegistrationView` if an account already exists with that email address.

**Context variables**

`password_reset_url`
: URL to the password reset page.

### account_exists_subject.txt

The subject of the email is set with this template: `account_exists_subject.txt`.

---

## federated/

All templates related to the OIDC authentication and registration can be found
in: `templates/hidp/federated`.

### account_link.html

Rendered by the `OIDCAccountLinkView`.

Redirects to `OIDCLinkedServicesView` after successfully linking the account to the
OIDC provider.

**Base template**: `base_post_login.html`

**Form template**: `federated/forms/account_link_form.html`

**Context variables**

`form`
: The account link form.

`cancel_url`
: Link for the cancel button.

`provider`
: The OIDC provider that the user is linking their account to.

`user_email`
: The email address of the user that is linking their account.

`provider_email`
: The email address retrieved from the OIDC provider.

### account_unlink.html

Rendered by the `OIDCAccountUnlinkView`.

Redirects to `OIDCLinkedServicesView` after successfully unlinking the account from the
OIDC provider.

**Base template**: `base_post_login.html`

**Form template**: `federated/forms/account_unlink_form.html`

**Context variables**

`form`
: The account unlink form.

`provider`
: The OIDC provider that the user is unlinking.

`cancel_url`
: URL for the cancel button.

### registration.html

Rendered by the `OIDCRegistrationView`.

**Base template**: `base_pre_login.html`

**Form template**: `federated/forms/registration_form.html`

**Context variables**

`form`
: The OIDC registration form.
