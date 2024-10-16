import django.db.models.deletion

from django.conf import settings
from django.db import migrations, models

import hidp.compat.uuid7


class Migration(migrations.Migration):
    initial = True

    dependencies = [
        migrations.swappable_dependency(settings.AUTH_USER_MODEL),
    ]

    operations = [
        migrations.CreateModel(
            name="OpenIdConnection",
            fields=[
                (
                    "id",
                    models.UUIDField(
                        default=hidp.compat.uuid7.uuid7,
                        editable=False,
                        primary_key=True,
                        serialize=False,
                    ),
                ),
                (
                    "user",
                    models.ForeignKey(
                        on_delete=django.db.models.deletion.CASCADE,
                        related_name="openid_connections",
                        to=settings.AUTH_USER_MODEL,
                    ),
                ),
                ("created_at", models.DateTimeField("created at", auto_now_add=True)),
                ("last_modified", models.DateTimeField("last modified", auto_now=True)),
                ("provider_key", models.CharField(max_length=100)),
                ("issuer_claim", models.CharField(max_length=255)),
                ("subject_claim", models.CharField(max_length=255)),
            ],
            options={
                "verbose_name": "OpenID connection",
                "verbose_name_plural": "OpenID connections",
                "unique_together": {("provider_key", "issuer_claim", "subject_claim")},
            },
        ),
    ]
