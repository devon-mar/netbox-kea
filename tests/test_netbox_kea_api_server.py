from typing import Any

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
"""  # noqa: UP031
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
def test_api_add_failures(body: dict[str, Any], nb_api: pynetbox.api):
    with pytest.raises(RequestError):
        nb_api.plugins.kea.servers.create(**body)


def test_server_create_basic_auth(
    nb_api: pynetbox.api,
    kea_basic_url: str,
    kea_basic_username: str,
    kea_basic_password: str,
) -> None:
    nb_api.plugins.kea.servers.create(
        name="basic",
        server_url=kea_basic_url,
        username=kea_basic_username,
        password=kea_basic_password,
    )


def test_server_create_client_cert(
    nb_api: pynetbox.api,
    kea_cert_url: str,
    kea_client_cert: str,
    kea_client_key: str,
    kea_ca: str,
) -> None:
    nb_api.plugins.kea.servers.create(
        name="client_cert",
        server_url=kea_cert_url,
        client_cert_path=kea_client_cert,
        client_key_path=kea_client_key,
        ca_file_path=kea_ca,
    )


def test_server_create_invalid_key(
    nb_api: pynetbox.api,
    kea_cert_url: str,
    kea_client_cert: str,
    kea_ca: str,
) -> None:
    with pytest.raises(RequestError):
        nb_api.plugins.kea.servers.create(
            name="client_cert",
            server_url=kea_cert_url,
            client_cert_path=kea_client_cert,
            client_key_path="foo",
            ca_file_path=kea_ca,
        )


def test_server_create_invalid_cert(
    nb_api: pynetbox.api,
    kea_cert_url: str,
    kea_client_key: str,
    kea_ca: str,
) -> None:
    with pytest.raises(RequestError):
        nb_api.plugins.kea.servers.create(
            name="client_cert",
            server_url=kea_cert_url,
            client_cert_path="foo",
            client_key_path=kea_client_key,
            ca_file_path=kea_ca,
        )


def test_server_create_key_no_cert(
    nb_api: pynetbox.api,
    kea_cert_url: str,
    kea_client_key: str,
    kea_ca: str,
) -> None:
    with pytest.raises(RequestError):
        nb_api.plugins.kea.servers.create(
            name="client_cert",
            server_url=kea_cert_url,
            client_key_path=kea_client_key,
            ca_file_path=kea_ca,
        )


def test_server_create_cert_no_key(
    nb_api: pynetbox.api,
    kea_cert_url: str,
    kea_client_cert: str,
    kea_ca: str,
) -> None:
    with pytest.raises(RequestError):
        nb_api.plugins.kea.servers.create(
            name="client_cert",
            server_url=kea_cert_url,
            client_cert_path=kea_client_cert,
            ca_file_path=kea_ca,
        )


def test_server_create_https(
    nb_api: pynetbox.api, kea_https_url: str, kea_ca: str
) -> None:
    nb_api.plugins.kea.servers.create(
        name="https",
        server_url=kea_https_url,
        ca_file_path=kea_ca,
    )


def test_server_create_ca_ssl_verify_false(
    nb_api: pynetbox.api, kea_https_url: str, kea_ca: str
) -> None:
    with pytest.raises(RequestError):
        nb_api.plugins.kea.servers.create(
            name="https",
            server_url=kea_https_url,
            ca_file_path=kea_ca,
            ssl_verify=False,
        )


def test_server_create_untrusted(nb_api: pynetbox.api, kea_https_url: str) -> None:
    with pytest.raises(RequestError):
        nb_api.plugins.kea.servers.create(
            name="https",
            server_url=kea_https_url,
        )


def test_server_create_no_ssl_verify(
    nb_api: pynetbox.api,
    kea_https_url: str,
) -> None:
    nb_api.plugins.kea.servers.create(
        name="insecure",
        server_url=kea_https_url,
        ssl_verify=False,
    )


def test_server_create_dhcp4_false_dhcp6_false(
    nb_api: pynetbox.api, kea_url: str
) -> None:
    with pytest.raises(RequestError):
        nb_api.plugins.kea.servers.create(
            name="no-services-enabled",
            server_url="http://kea-ctrl-agent:8000",
            dhcp4=False,
            dhcp6=False,
        )
