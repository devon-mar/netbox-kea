from netbox.filtersets import NetBoxModelFilterSet

from .models import Server


class ServerFilterSet(NetBoxModelFilterSet):
    class Meta:
        model = Server
        fields = ("id", "name", "server_url")
