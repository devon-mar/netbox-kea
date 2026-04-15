from typing import Any

import pynetbox
import pytest
import requests
from pynetbox.core.query import RequestError

from . import constants


def test_server_api_add_delete(nb_api: pynetbox.api):
    name = "test"

    server = nb_api.plugins.kea.servers.create(
        name=name, dhcp6_url=constants.KEA6_URL, dhcp4_url=constants.KEA4_URL
    )
    assert server.name == name
    assert server.dhcp4_url == constants.KEA4_URL
    assert server.dhcp6_url == constants.KEA6_URL

    # We shouldn't be able to add a server with the same name
    with pytest.raises(RequestError):
        nb_api.plugins.kea.servers.create(
            name=name, dhcp6_url=constants.KEA6_URL, dhcp4_url=constants.KEA4_URL
        )

    new_name = "new-name"
    server.update({"name": new_name})
    new_server = nb_api.plugins.kea.servers.get(name=new_name)
    assert new_server.name == new_name
    assert hasattr(new_server, "password") is False

    assert server.delete() is True


def test_server_api_bulk_actions(nb_api: pynetbox.api):
    servers = nb_api.plugins.kea.servers.create(
        [
            {"name": "server1", "dhcp4_url": constants.KEA4_URL},
            {"name": "server2", "dhcp6_url": constants.KEA6_URL},
        ]
    )
    for s in servers:
        s.name += "-updated"
    nb_api.plugins.kea.servers.update(servers)

    assert nb_api.plugins.kea.servers.get(name="server1-updated") is not None
    assert nb_api.plugins.kea.servers.delete(servers) is True


def test_graphql(nb_api: pynetbox.api, nb_http: requests.Session):
    server = nb_api.plugins.kea.servers.create(
        name="gql-test", dhcp6_url=constants.KEA6_URL, dhcp4_url=constants.KEA4_URL
    )
    r = nb_http.post(
        "http://localhost:8000/graphql/",
        json={
            "query": """
{
  server_list {
    id
    name
    dhcp4_url
    dhcp6_url
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
                    "dhcp4_url": server.dhcp4_url,
                    "dhcp6_url": server.dhcp6_url,
                }
            ]
        }
    }

    # Ensure password is not a valid field
    r = nb_http.post(
        "http://localhost:8000/graphql/",
        json={
            "query": """
{
  server_list {
    id
    password
  }
}
"""
        },
    )
    assert r.ok is True

    r_json = r.json()
    assert r_json["data"] is None
    assert len(r_json["errors"]) == 1
    assert (
        r_json["errors"][0]["message"]
        == "Cannot query field 'password' on type 'ServerType'."
    )

    r = nb_http.post(
        "http://localhost:8000/graphql/",
        json={
            "query": """
{
    server(id: %s) {
    id
    name
    dhcp4_url
    dhcp6_url
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
                "dhcp4_url": server.dhcp4_url,
                "dhcp6_url": server.dhcp6_url,
            }
        }
    }


@pytest.mark.parametrize(
    ("body",),
    (
        pytest.param(
            {
                "name": "cert-no-key",
                # TODO
                "dhcp4_url": "http://kea-dhcp4:8000",
                "client_cert_path": "/root/mycert.crt",
            },
            id="client-cert-no-key",
        ),
    ),
)
def test_api_add_failures(body: dict[str, Any], nb_api: pynetbox.api):
    with pytest.raises(RequestError):
        nb_api.plugins.kea.servers.create(**body)


def test_server_create_basic_auth(nb_api: pynetbox.api) -> None:
    nb_api.plugins.kea.servers.create(
        name="basic",
        dhcp6_url=constants.KEA6_URL_BASIC,
        dhcp4_url=constants.KEA4_URL_BASIC,
        username=constants.KEA_BASIC_USERNAME,
        password=constants.KEA_BASIC_PASSWORD,
        ca_file_path=constants.KEA_CA,
    )


def test_server_create_client_cert(nb_api: pynetbox.api) -> None:
    nb_api.plugins.kea.servers.create(
        name="client_cert",
        dhcp6_url=constants.KEA6_URL_CERT,
        dhcp4_url=constants.KEA4_URL_CERT,
        client_cert_path=constants.KEA_CLIENT_CERT,
        client_key_path=constants.KEA_CLIENT_KEY,
        ca_file_path=constants.KEA_CA,
    )


def test_server_create_invalid_key(nb_api: pynetbox.api) -> None:
    with pytest.raises(RequestError):
        nb_api.plugins.kea.servers.create(
            name="client_cert",
            dhcp6_url=constants.KEA6_URL_CERT,
            dhcp4_url=constants.KEA4_URL_CERT,
            client_cert_path=constants.KEA_CLIENT_CERT,
            client_key_path="foo",
            ca_file_path=constants.KEA_CA,
        )


def test_server_create_invalid_cert(
    nb_api: pynetbox.api,
) -> None:
    with pytest.raises(RequestError):
        nb_api.plugins.kea.servers.create(
            name="client_cert",
            dhcp6_url=constants.KEA6_URL_CERT,
            dhcp4_url=constants.KEA4_URL_CERT,
            client_cert_path="foo",
            client_key_path=constants.KEA_CLIENT_KEY,
            ca_file_path=constants.KEA_CA,
        )


def test_server_create_key_no_cert(nb_api: pynetbox.api) -> None:
    with pytest.raises(RequestError):
        nb_api.plugins.kea.servers.create(
            name="client_cert",
            dhcp6_url=constants.KEA6_URL_CERT,
            dhcp4_url=constants.KEA4_URL_CERT,
            client_key_path=constants.KEA_CLIENT_KEY,
            ca_file_path=constants.KEA_CA,
        )


def test_server_create_cert_no_key(nb_api: pynetbox.api) -> None:
    with pytest.raises(RequestError):
        nb_api.plugins.kea.servers.create(
            name="client_cert",
            dhcp6_url=constants.KEA6_URL_CERT,
            dhcp4_url=constants.KEA4_URL_CERT,
            client_cert_path=constants.KEA_CLIENT_CERT,
            ca_file_path=constants.KEA_CA,
        )


def test_server_create_https(nb_api: pynetbox.api) -> None:
    nb_api.plugins.kea.servers.create(
        name="https",
        dhcp6_url=constants.KEA6_URL_SECURE,
        ca_file_path=constants.KEA_CA,
    )


def test_server_create_ca_ssl_verify_false(nb_api: pynetbox.api) -> None:
    with pytest.raises(RequestError):
        nb_api.plugins.kea.servers.create(
            name="https",
            dhcp4_url=constants.KEA4_URL_SECURE,
            ca_file_path=constants.KEA_CA,
            ssl_verify=False,
        )


def test_server_create_untrusted(nb_api: pynetbox.api) -> None:
    with pytest.raises(RequestError):
        nb_api.plugins.kea.servers.create(
            name="https",
            dhcp4_url=constants.KEA4_URL_SECURE,
        )


def test_server_create_no_ssl_verify(nb_api: pynetbox.api) -> None:
    nb_api.plugins.kea.servers.create(
        name="insecure",
        dhcp6_url=constants.KEA6_URL_SECURE,
        ssl_verify=False,
    )


def test_server_create_dhcp4_false_dhcp6_false(nb_api: pynetbox.api) -> None:
    with pytest.raises(RequestError):
        nb_api.plugins.kea.servers.create(
            name="no-services-enabled",
        )


def test_server_api_changelog_password_censored(
    nb_api: pynetbox.api, nb_http: requests.Session
):
    name = "changelog-test"

    server = nb_api.plugins.kea.servers.create(name=name, dhcp6_url=constants.KEA6_URL)
    assert server.name == name

    version = nb_api.status()["netbox-version"]

    object_changes = (
        nb_api.extras.object_changes
        if version.startswith("4.0")
        else nb_api.core.object_changes
    )

    # pynetbox has a special model for core.object_changes but not for extras.object_changes
    # (as of v7.6.1). Cast to dict to make it consistent.
    changelog_create = dict(
        object_changes.get(
            changed_object_id=server.id,
            changed_object_type="netbox_kea.server",
            action="create",
        )
    )
    assert changelog_create["prechange_data"] == {}
    assert changelog_create["postchange_data"]["password"] is None

    # Cannot update through pynetbox since the password field is write only.
    def update_password(password: str | None) -> None:
        resp = nb_http.patch(
            server.url,
            json={"password": password},
            timeout=20,
        )
        resp.raise_for_status()

    # Set the password
    update_password("password0")

    changelog_update0 = dict(
        object_changes.get(
            changed_object_id=server.id,
            changed_object_type="netbox_kea.server",
            action="update",
        )
    )
    assert changelog_update0["prechange_data"]["password"] is None
    assert changelog_update0["postchange_data"]["password"] == "***CHANGED***"

    # Update the password
    update_password("password1")

    changelog_update1 = dict(
        object_changes.get(
            id__gt=changelog_update0["id"],
            changed_object_id=server.id,
            changed_object_type="netbox_kea.server",
            action="update",
        )
    )
    assert changelog_update1["prechange_data"]["password"] == "********"
    assert changelog_update1["postchange_data"]["password"] == "***CHANGED***"

    # Remove the password
    update_password(None)
    changelog_update2 = dict(
        object_changes.get(
            id__gt=changelog_update1["id"],
            changed_object_id=server.id,
            changed_object_type="netbox_kea.server",
            action="update",
        )
    )
    assert changelog_update2["prechange_data"]["password"] == "********"
    assert changelog_update2["postchange_data"]["password"] is None

    # Delete the server
    assert server.delete() is True
    changelog_delete = dict(
        object_changes.get(
            changed_object_id=server.id,
            changed_object_type="netbox_kea.server",
            action="delete",
        )
    )
    assert changelog_delete["prechange_data"]["password"] is None
    assert changelog_delete["postchange_data"] == {}
