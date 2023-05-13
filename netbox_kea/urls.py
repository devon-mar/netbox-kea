from django.urls import include, path
from utilities.urls import get_model_urls

from . import views

urlpatterns = (
    path("servers/", views.ServerListView.as_view(), name="server_list"),
    path("servers/add/", views.ServerEditView.as_view(), name="server_add"),
    path(
        "servers/delete/",
        views.ServerBulkDeleteView.as_view(),
        name="server_bulk_delete",
    ),
    path(
        "servers/<int:pk>/leases6/delete/",
        views.ServerLeases6DeleteView.as_view(),
        name="server_leases6_delete",
    ),
    path(
        "servers/<int:pk>/leases4/delete/",
        views.ServerLeases4DeleteView.as_view(),
        name="server_leases4_delete",
    ),
    path("servers/<int:pk>/", include(get_model_urls("netbox_kea", "server"))),
)
