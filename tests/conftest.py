import pynetbox
import pytest
import requests

from . import constants


@pytest.fixture(scope="session")
def netbox_token() -> str:
    resp = requests.post(
        f"{constants.NETBOX_URL}/api/users/tokens/provision/",
        json={"username": "admin", "password": "admin"},
    )
    resp.raise_for_status()

    data = resp.json()
    if data.get("version") == 2:
        return f"nbt_{data['key']}.{data['token']}"
    else:
        return data["key"]


@pytest.fixture(scope="session")
def netbox_username() -> str:
    return "admin"


@pytest.fixture(scope="session")
def netbox_password() -> str:
    return "admin"


@pytest.fixture(scope="session")
def nb_http(netbox_token: str) -> requests.Session:
    s = requests.Session()
    auth_prefix = "Bearer" if netbox_token.startswith("nbt_") else "Token"
    s.headers.update(
        {
            "Authorization": f"{auth_prefix} {netbox_token}",
            "Content-Type": "application/json",
            "Accept": "application/json",
        }
    )
    return s


@pytest.fixture(scope="session", autouse=True)
def nb_api(netbox_token: str) -> pynetbox.api:
    api = pynetbox.api(constants.NETBOX_URL, token=netbox_token)
    api.plugins.kea.servers.delete(api.plugins.kea.servers.all())

    return api
