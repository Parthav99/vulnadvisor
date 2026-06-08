"""URLconf routing a request to the vulnerable view."""

from django.urls import path

from . import views

urlpatterns = [
    path("config/", views.parse_config, name="parse-config"),
]
