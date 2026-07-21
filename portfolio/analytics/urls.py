from django.urls import path

from . import views


app_name = "analytics"

urlpatterns = [
    path("", views.dashboard, name="dashboard"),
    path("data/", views.dashboard_data, name="dashboard_data"),
    path("visitor/<int:pk>/", views.visitor_detail, name="visitor_detail"),
    path("export.csv", views.export_csv, name="export_csv"),
    path("event/<int:pk>/resolve/", views.resolve_event, name="resolve_event"),
]
