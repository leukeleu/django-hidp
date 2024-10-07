# Users

HIdP does not provide a concrete user model. Instead, it provides a base user model
that you must inherit from in your own user model. This allows you to define
a user model that fits your application's needs while still being able to adhere to
the requirements of HIdP.

## Model

To create a user model, inherit from `hidp.accounts.models.BaseUser`, this model
provides the fields and methods required by HIdP, Django and Django Admin.

Don't forget to point `AUTH_USER_MODEL` in your setting to your custom user model.

```{eval-rst}
.. autoclass:: hidp.accounts.models.BaseUser
  :members:
```

## QuerySet

By inheriting from `BaseUser`, your user model will also have access to a custom query set
implementation that provides some convenience methods for querying users.

```{eval-rst}
.. autoclass:: hidp.accounts.models.UserQuerySet
  :members:
```

## Manager

The manager (`objects`) of your user model will be an instance of `UserManager`, which
exports the same methods as `UserQuerySet` and additional methods for creating users
inherited from Django's `UserManager`.

```{eval-rst}
.. autoclass:: hidp.accounts.models.UserManager
  :members:
```
