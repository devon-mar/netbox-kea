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


@pytest.fixture
def kea_basic_url() -> str:
    return "http://nginx"


@pytest.fixture
def kea_basic_username() -> str:
    return "kea"


@pytest.fixture
def kea_basic_password() -> str:
    return "kea"


@pytest.fixture
def kea_https_url() -> str:
    return "https://nginx"


@pytest.fixture
def kea_cert_url() -> str:
    return "https://nginx:444"


@pytest.fixture
def kea_client_cert() -> str:
    return "/certs/netbox.crt"


@pytest.fixture
def kea_client_key() -> str:
    return "/certs/netbox.key"


@pytest.fixture
def kea_ca() -> str:
    return "/certs/nginx.crt"
