# Terms of Service

## TermsOfServiceMixin

This project contains a `TermsOfServiceMixin` that enforces user agreement to your Terms of Service (ToS) during form-based account registration. It ensures users explicitly consent by checking a box, and records the timestamp of that agreement in the user model.

**Features**

- Adds a **required checkbox** to forms for user ToS acceptance.
- Records agreement by setting a timestamp on the `user.agreed_to_tos` field.

### Disabling the Terms of Service Checkbox

If you do not want to include a ToS checkbox, override the UserCreationForm to set the `agreed_to_tos` field to `None`.

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

  This approach keeps your code compatible with the mixin while cleanly disabling ToS enforcement when not required.

## Terms of Service template

HIdP contains a default [Terms of Service template](project:templates.md) located at `packages/hidp/hidp/templates/hidp/accounts/tos.html`. This template is a placeholder and **is not suitable for production use**. You should customize it to reflect your actual terms, and ensure it complies with your policies, supported languages, and legal requirements in your jurisdiction.
