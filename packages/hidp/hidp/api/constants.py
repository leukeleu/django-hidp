from django.db import models


class LoginGrant(models.TextChoices):
    SESSION = "session", "Session"
    BEARER = "bearer", "Bearer"
