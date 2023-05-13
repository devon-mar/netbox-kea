from graphene import ObjectType
from netbox.graphql.fields import ObjectField, ObjectListField
from netbox.graphql.types import NetBoxObjectType

from .models import Server


class ServerType(NetBoxObjectType):
    class Meta:
        model = Server
        fields = "__all__"


class Query(ObjectType):
    server = ObjectField(ServerType)
    server_list = ObjectListField(ServerType)


schema = Query
