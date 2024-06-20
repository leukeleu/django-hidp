from django.contrib import admin
from django.contrib.auth.admin import UserAdmin as BaseUserAdmin
from django.db.models.functions import Collate
from django.utils.translation import gettext_lazy as _

from .models import User


@admin.register(User)
class UserAdmin(BaseUserAdmin):
    fieldsets = (
        (None, {"fields": ("email", "password")}),
        (
            _("Personal info"),
            {
                "fields": (
                    "first_name",
                    "last_name",
                )
            },
        ),
        (
            _("Permissions"),
            {
                "fields": (
                    "is_active",
                    "is_staff",
                    "is_superuser",
                    "groups",
                    "user_permissions",
                ),
            },
        ),
        (
            _("Important dates"),
            {
                "fields": (
                    "date_joined",
                    "last_login",
                    "email_verified",
                    "last_modified",
                )
            },
        ),
    )
    add_fieldsets = (
        (
            None,
            {
                "classes": ("wide",),
                "fields": (
                    "email",
                    "first_name",
                    "last_name",
                    "password1",
                    "password2",
                ),
            },
        ),
    )
    list_display = (
        "email",
        "first_name",
        "last_name",
        "is_staff",
    )
    search_fields = (
        "email_ci",
        "first_name",
        "last_name",
    )
    readonly_fields = (
        "date_joined",
        "last_login",
        "email_verified",
        "last_modified",
    )
    ordering = ("pk",)

    def get_queryset(self, request):
        # Allow searching by case-insensitive email
        # https://adamj.eu/tech/2023/02/23/migrate-django-postgresql-ci-fields-case-insensitive-collation/#adjust-queries
        return (
            super()
            .get_queryset(request)
            .annotate(email_ci=Collate("email", collation="und-x-icu"))
        )
