from django.contrib import admin
from django.urls import path
from django.views.generic.base import TemplateView

from .router import router

urlpatterns = [
    # Project
    path("", TemplateView.as_view(template_name="base.html")),
    *router.urls,
    # Django Admin
    path("django-admin/", admin.site.urls),
]
