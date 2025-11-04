from django.db import models


class LoginType(models.TextChoices):
    SESSION = "session", "Session"
    BEARER = "bearer", "Bearer"
