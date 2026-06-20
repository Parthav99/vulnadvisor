"""URLconf wiring the object-state views — the registration that makes them entry points."""

from django.urls import path

from . import views

urlpatterns = [
    path("store/<str:raw>/", views.StoreView.as_view()),
    path("run/<str:raw>/", views.run_view),
    path("data/<str:raw>/", views.data_view),
    path("setter/<str:raw>/", views.setter_view),
    path("dynamic/<str:raw>/", views.dynamic_view),
    path("literal/<str:raw>/", views.literal_view),
    path("untracked/<str:raw>/", views.untracked_view),
]
