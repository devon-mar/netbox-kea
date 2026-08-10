from netbox.api.viewsets import NetBoxModelViewSet

from .. import filtersets, models
from .serializers import ServerSerializer


class ServerViewSet(NetBoxModelViewSet):
    queryset = models.Server.objects.prefetch_related("tags").order_by("-pk")
    filterset_class = filtersets.ServerFilterSet
    serializer_class = ServerSerializer
