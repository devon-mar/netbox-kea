import pynetbox
import pytest
import requests


@pytest.fixture(scope="session")
def netbox_url() -> str:
    return "http://localhost:8000"


@pytest.fixture(scope="session")
def netbox_token() -> str:
    return "0123456789abcdef0123456789abcdef01234567"


@pytest.fixture(scope="session")
def netbox_username() -> str:
    return "admin"


@pytest.fixture(scope="session")
def netbox_password() -> str:
    return "admin"


@pytest.fixture(scope="session")
def kea_url() -> str:
    return "http://kea-ctrl-agent:8000"


@pytest.fixture(scope="session")
def nb_http(netbox_token: str) -> requests.Session:
    s = requests.Session()
    s.headers.update(
        {
            "Authorization": f"Token {netbox_token}",
            "Content-Type": "application/json",
            "Accept": "application/json",
        }
    )
    return s


@pytest.fixture(scope="session", autouse=True)
def nb_api(netbox_url: str, netbox_token: str) -> pynetbox.api:
    api = pynetbox.api(netbox_url, token=netbox_token)
    api.plugins.kea.servers.delete(api.plugins.kea.servers.all())

    return api
