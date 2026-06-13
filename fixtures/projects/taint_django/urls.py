"""URLconf wiring the views — the registration that makes the views entry points (cross-file)."""

from django.urls import path

from . import views

urlpatterns = [
    path("config/", views.ConfigView.as_view()),
    path("report/<str:name>/", views.run_report),
]
