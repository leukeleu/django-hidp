# Terms of Service

## TermsOfServiceMixin

This project contains a `TermsOfServiceMixin` that enforces user agreement to your Terms of Service (ToS) during form-based account registration. It ensures users explicitly consent by checking a box, and records the timestamp of that agreement in the user model.

### Features

- Adds a **required checkbox** to forms for user ToS acceptance.
- Records agreement by setting a timestamp on the `user.agreed_to_tos` field.
- Can be reused across different forms and adapted per context (e.g. OIDC registration vs. local signup).

### Behavior

The mixin provides two key methods:

- `create_agreed_to_tos_field()` builds a labeled checkbox that includes a hyperlink to the Terms of Service.
- `set_agreed_to_tos(user)` checks if the box was ticked and updates the `user.agreed_to_tos` timestamp accordingly.

### Disabling the Terms of Service Checkbox

If you do not want to include a ToS checkbox, override the `UserCreationForm` to set the `agreed_to_tos` field to `None`.

- Set `agreed_to_tos` to `None` in your form:

   ```python
   CustomUserCreationForm(UserCreationForm):
       agreed_to_tos = None
   ```

- `set_agreed_to_tos()` will **silently skip** setting the timestamp if the field is missing or not checked:

   ```python
   def save(self, *, commit=True):
       user = super().save(commit=False)
       self.set_agreed_to_tos(user)  # Safe to call even without the field
       if commit:
           user.save()
       return user
   ```

- Override the `RegistrationView` (and `OIDCRegistrationView` if used) to use your custom form class:

   ```python
   from hidp.accounts.views import RegistrationView

   class CustomRegistrationView(RegistrationView):
       form_class = CustomUserCreationForm
   ```

- Ensure your custom view is registered in your URL configuration:

    ```python
    from django.urls import path
    from .views import CustomRegistrationView

    urlpatterns = [
        path('signup/', CustomRegistrationView.as_view(), name='register'),  # Above the hidp URLs
        path("", include(hidp_urls)),
    ]
    ```

## Terms of Service Template

HIdP contains a default [Terms of Service template](project:templates.md) located at:

```
packages/hidp/hidp/templates/hidp/accounts/tos.html
```

This template is a placeholder and **is not suitable for production use**.

You should:

- Replace the content with your actual legal terms.
- Ensure translations are added for supported languages.
- Consult legal counsel to meet compliance and data protection obligations in your jurisdiction.
