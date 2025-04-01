from django.urls import include, path

from ..accounts import account_registration_urls
from .shared_urls import urlpatterns as base_urlpatterns

urlpatterns = [path("", include(account_registration_urls)), *base_urlpatterns]
