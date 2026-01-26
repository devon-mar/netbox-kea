import strawberry
import strawberry_django
from netbox.graphql.types import NetBoxObjectType

from . import models


@strawberry_django.type(
    models.Server,
    fields=(
        "id",
        "name",
        "server_url",
        "username",
        "ssl_verify",
        "client_cert_path",
        "client_key_path",
        "ca_file_path",
        "dhcp6",
        "dhcp4",
    ),
)
class ServerType(NetBoxObjectType):
    pass


@strawberry.type
class Query:
    @strawberry.field
    def server(self, id: int) -> ServerType:
        return models.Server.objects.get(pk=id)

    server_list: list[ServerType] = strawberry_django.field()


schema = [Query]
