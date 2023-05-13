from typing import Any, Dict

import pynetbox
import pytest
import requests
from pynetbox.core.query import RequestError


def test_server_api_add_delete(nb_api: pynetbox.api):
    name = "test"
    server_url = "http://kea-ctrl-agent:8000"

    server = nb_api.plugins.kea.servers.create(name=name, server_url=server_url)
    assert server.name == name
    assert server.server_url == server_url

    # We shouldn't be able to add a server with the same name
    with pytest.raises(RequestError):
        nb_api.plugins.kea.servers.create(
            name=name, server_url="http://kea-ctrl-agent:8000"
        )

    new_name = "new-name"
    server.update({"name": new_name})
    new_server = nb_api.plugins.kea.servers.get(name=new_name)
    assert new_server.name == new_name

    assert server.delete() is True


def test_server_api_bulk_actions(nb_api: pynetbox.api):
    servers = nb_api.plugins.kea.servers.create(
        [
            {"name": "server1", "server_url": "http://kea-ctrl-agent:8000"},
            {"name": "server2", "server_url": "http://kea-ctrl-agent:8000"},
        ]
    )
    for s in servers:
        s.name += "-updated"
    nb_api.plugins.kea.servers.update(servers)

    assert nb_api.plugins.kea.servers.get(name="server1-updated") is not None
    assert nb_api.plugins.kea.servers.delete(servers) is True


def test_graphql(nb_api: pynetbox.api, nb_http: requests.Session):
    server = nb_api.plugins.kea.servers.create(
        name="gql-test", server_url="http://kea-ctrl-agent:8000"
    )
    r = nb_http.post(
        "http://localhost:8000/graphql/",
        json={
            "query": """
{
  server_list {
    id
    name
    server_url
  }
}
"""
        },
    )
    assert r.ok is True

    r_json = r.json()
    assert r_json == {
        "data": {
            "server_list": [
                {
                    "id": str(server.id),
                    "name": server.name,
                    "server_url": server.server_url,
                }
            ]
        }
    }

    r = nb_http.post(
        "http://localhost:8000/graphql/",
        json={
            "query": """
{
    server(id: %s) {
    id
    name
    server_url
  }
}
"""
            % server.id
        },
    )
    assert r.ok is True
    r_json = r.json()
    assert r_json == {
        "data": {
            "server": {
                "id": str(server.id),
                "name": server.name,
                "server_url": server.server_url,
            }
        }
    }


@pytest.mark.parametrize(
    ("body",),
    (
        pytest.param(
            {
                "name": "cert-no-key",
                "server_url": "http://kea-ctrl-agent:8000",
                "client_cert_path": "/root/mycert.crt",
            },
            id="client-cert-no-key",
        ),
    ),
)
def test_api_add_failures(body: Dict[str, Any], nb_api: pynetbox.api):
    with pytest.raises(RequestError):
        nb_api.plugins.kea.servers.create(**body)
