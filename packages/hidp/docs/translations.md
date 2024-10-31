# Multi-language support

HIdP is built with multi-language support in mind. While all strings are in English by default, they
are all marked for translation using Django's built-in translation system.

## Enabling translations for your project

To enable translations for your project, you need to add the following to your Django settings:

```python
# settings.py
LANGUAGE_CODE = "en"  # Default language
LANGUAGES = [  # All languages supported by your project
    ("en", "English"),
    ("nl", "Nederlands"),
]

MIDDLEWARE = [
    ...,
    # Django's locale middleware to activate translations based on user's language preference
    "django.middleware.locale.LocaleMiddleware",
    ...,
]
```

Make sure to read the [Django documentation](https://docs.djangoproject.com/en/stable/topics/i18n/translation/#how-django-discovers-language-preference)
for a more detailed explanation on how to configure these settings and what this middleware does.

The [Django documentation](https://docs.djangoproject.com/en/stable/topics/i18n/translation/#the-set-language-redirect-view)
also has a section on how to let users choose their language preference.

If you use HIdP as an [OIDC provider](project:./configure-as-oidc-provider.md), it is recommended to also
add the following middleware, which sets the user's language preference based on the OIDC `ui_locales` parameter:

```python
MIDDLEWARE = [
    ...,
    # Set the user's language preference based on the OIDC `ui_locales` parameter
    # This middleware should together with Django's `LocaleMiddleware`
    "hidp.oidc_provider.middleware.UiLocalesMiddleware",
    ...,
]
```

## Translating strings

HIdP ships with Dutch translations out of the box, and a message catalog template is available in the
`hidp/locale` directory. You can use this template to create your own translations.

In order to translate strings in your project, you need to create a message catalog for each language you
want to support.

First configure the `LOCALE_PATHS` setting in your Django settings:

```python
# settings.py
LOCALE_PATHS = [
    BASE_DIR / "locale"
]
```

Inside the `locale` directory, create a subdirectory for each language you want to support. For example,

```
locale/
    de/
        LC_MESSAGES/
            django.po
```

Make sure to also include the language code in the `LANGUAGES` setting in your Django settings.

Copy the contents of the `django.pot` file from the `hidp/locale` directory into the `django.po` file in the
language subdirectory and start translating the strings.

After translating the strings, compile this message catalog using Django's `compilemessages` management command:

```bash
python manage.py compilemessages -l de
```

:::{note}
If you are also translating strings from your own project, in addition to HIdP, it is recommended to keep
the translations of HIdP and your project separate.

You can do this by configuring multiple `LOCALE_PATHS` in your Django settings:

```python
# settings.py
LOCALE_PATHS = [
    BASE_DIR / "locale",  # Your project's locale directory
    BASE_DIR / "hidp/locale",  # HIdP's locale directory
]
```
:::
