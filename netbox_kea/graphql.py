import strawberry
import strawberry_django

from . import models


@strawberry_django.type(
    models.Server,
    fields="__all__",
)
class ServerType:
    pass


@strawberry.type
class Query:
    @strawberry.field
    def server(self, id: int) -> ServerType:
        return models.Server.objects.get(pk=id)

    server_list: list[ServerType] = strawberry_django.field()


schema = [Query]
