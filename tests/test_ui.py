import csv
import re
from datetime import datetime, timezone
from typing import Any, Literal, Optional, Sequence

import pynetbox
import pytest
import requests
from netaddr import EUI, IPAddress, IPNetwork, mac_unix_expanded
from playwright.sync_api import Page, expect

from . import constants

# This is linked from netbox_kea to avoid import errors
from .kea import KeaClient


@pytest.fixture
def requests_session(nb_api: pynetbox.api) -> requests.Session:
    s = requests.Session()
    s.headers.update(
        {
            "Authorization": f"Token {nb_api.token}",
            "Content-Type": "application/json",
            "Accept": "application/json",
        }
    )
    return s


@pytest.fixture(autouse=True)
def clear_leases(kea_client: KeaClient) -> None:
    kea_client.command("lease4-wipe", service=["dhcp4"], check=(0, 3))
    kea_client.command("lease6-wipe", service=["dhcp6"], check=(0, 3))


@pytest.fixture(autouse=True)
def reset_user_preferences(
    requests_session: requests.Session, nb_api: pynetbox.api
) -> None:
    r = requests_session.get(url=f"{nb_api.base_url}/users/config/")
    r.raise_for_status()
    tables_config = r.json().get("tables", {})

    # pynetbox doesn't support this endpoint
    requests_session.patch(
        url=f"{nb_api.base_url}/users/config/",
        json={"tables": {k: {} for k in tables_config}},
    ).raise_for_status()

    # restore pagination
    requests_session.patch(
        url=f"{nb_api.base_url}/users/config/",
        json={"pagination": {"placement": "bottom"}},
    ).raise_for_status()


@pytest.fixture
def with_test_server(
    nb_api: pynetbox.api, kea_url: str, page: Page, netbox_login: None, plugin_base: str
):
    server = nb_api.plugins.kea.servers.create(name="test", server_url=kea_url)
    page.goto(f"{plugin_base}/servers/{server.id}/")
    yield
    server.delete()


@pytest.fixture
def with_test_server_only6(
    nb_api: pynetbox.api, kea_url: str, page: Page, netbox_login: None, plugin_base: str
):
    server = nb_api.plugins.kea.servers.create(
        name="only6", server_url=kea_url, dhcp4=False, dhcp6=True
    )
    page.goto(f"{plugin_base}/servers/{server.id}/")
    yield
    server.delete()


@pytest.fixture
def with_test_server_only4(
    nb_api: pynetbox.api, kea_url: str, page: Page, netbox_login: None, plugin_base: str
):
    server = nb_api.plugins.kea.servers.create(
        name="only4", server_url=kea_url, dhcp4=True, dhcp6=False
    )
    page.goto(f"{plugin_base}/servers/{server.id}/")
    yield
    server.delete()


@pytest.fixture
def kea_client() -> KeaClient:
    return KeaClient("http://localhost:8001")


@pytest.fixture
def kea(with_test_server: None, kea_client: KeaClient) -> KeaClient:
    return kea_client


@pytest.fixture
def plugin_base(netbox_url: str) -> str:
    return f"{netbox_url}/plugins/kea"


@pytest.fixture
def lease6(kea: KeaClient) -> dict[str, Any]:
    lease_ip = "2001:db8:1::1"
    kea.command(
        "lease6-add",
        service=["dhcp6"],
        arguments={
            "ip-address": lease_ip,
            "duid": "01:02:03:04:05:06:07:08",
            "hw-address": "08:08:08:08:08:08",
            "iaid": 1,
            "valid-lft": 3600,
            "hostname": "test-lease6",
            "preferred-lft": 7200,
        },
    )
    lease = kea.command(
        "lease6-get", arguments={"ip-address": lease_ip}, service=["dhcp6"]
    )[0]["arguments"]
    assert lease is not None
    return lease


@pytest.fixture
def lease6_netbox_device(
    nb_api: pynetbox.api,
    test_device_type: int,
    test_device_role: int,
    test_site: int,
    lease6: dict[str, Any],
):
    version = nb_api.version
    device_role_key = "device_role" if version == "3.5" else "role"

    lease_ip = lease6["ip-address"]

    device = nb_api.dcim.devices.create(
        name=lease6["hostname"],
        device_type=test_device_type,
        site=test_site,
        **{device_role_key: test_device_role},
    )

    interface = nb_api.dcim.interfaces.create(
        name="eth0",
        type="1000base-t",
        device=device.id,
        mac_address=lease6["hw-address"],
    )

    ip = nb_api.ipam.ip_addresses.create(
        address=f"{lease_ip}/64",
        assigned_object_type="dcim.interface",
        assigned_object_id=interface.id,
    )

    yield lease_ip
    ip.delete()
    interface.delete()
    device.delete()


@pytest.fixture
def lease6_netbox_vm(
    nb_api: pynetbox.api,
    test_cluster: int,
    test_device_role: int,
    lease6: dict[str, Any],
):
    lease_ip = lease6["ip-address"]

    vm = nb_api.virtualization.virtual_machines.create(
        name=lease6["hostname"],
        cluster=test_cluster,
        role=test_device_role,
    )
    interface = nb_api.virtualization.interfaces.create(
        name="eth0", virtual_machine=vm.id, mac_address=lease6["hw-address"]
    )
    ip = nb_api.ipam.ip_addresses.create(
        address=f"{lease_ip}/64",
        assigned_object_type="virtualization.vminterface",
        assigned_object_id=interface.id,
    )

    yield lease_ip

    ip.delete()
    interface.delete()
    vm.delete()


@pytest.fixture
def lease6_netbox_ip(nb_api: pynetbox.api, lease6: dict[str, Any]):
    lease_ip = lease6["ip-address"]
    ip = nb_api.ipam.ip_addresses.create(address=f"{lease_ip}/64")
    yield lease_ip
    ip.delete()


@pytest.fixture
def lease4(kea: KeaClient) -> dict[str, Any]:
    lease_ip = "192.0.2.1"
    kea.command(
        "lease4-add",
        service=["dhcp4"],
        arguments={
            "ip-address": lease_ip,
            "hw-address": "08:08:08:08:08:08",
            "client-id": "18:08:08:08:08:08",
            "hostname": "test-lease4",
        },
    )
    lease = kea.command(
        "lease4-get", arguments={"ip-address": lease_ip}, service=["dhcp4"]
    )[0]["arguments"]
    assert lease is not None
    return lease


@pytest.fixture
def lease4_netbox_device(
    nb_api: pynetbox.api,
    test_device_type: int,
    test_device_role: int,
    test_site: int,
    lease4: dict[str, Any],
):
    version = nb_api.version
    device_role_key = "device_role" if version == "3.5" else "role"

    lease_ip = lease4["ip-address"]

    device = nb_api.dcim.devices.create(
        name=lease4["hostname"],
        device_type=test_device_type,
        site=test_site,
        **{device_role_key: test_device_role},
    )

    interface = nb_api.dcim.interfaces.create(
        name="eth0",
        type="1000base-t",
        device=device.id,
        mac_address=lease4["hw-address"],
    )

    ip = nb_api.ipam.ip_addresses.create(
        address=f"{lease_ip}/24",
        assigned_object_type="dcim.interface",
        assigned_object_id=interface.id,
    )

    yield lease_ip
    ip.delete()
    interface.delete()
    device.delete()


@pytest.fixture
def lease4_netbox_vm(
    nb_api: pynetbox.api,
    test_cluster: int,
    test_device_role: int,
    lease4: dict[str, Any],
):
    lease_ip = lease4["ip-address"]

    vm = nb_api.virtualization.virtual_machines.create(
        name=lease4["hostname"],
        cluster=test_cluster,
        role=test_device_role,
    )
    interface = nb_api.virtualization.interfaces.create(
        name="eth0", virtual_machine=vm.id, mac_address=lease4["hw-address"]
    )
    ip = nb_api.ipam.ip_addresses.create(
        address=f"{lease_ip}/24",
        assigned_object_type="virtualization.vminterface",
        assigned_object_id=interface.id,
    )

    yield lease_ip

    ip.delete()
    interface.delete()
    vm.delete()


@pytest.fixture
def lease4_netbox_ip(nb_api: pynetbox.api, lease4: dict[str, Any]):
    lease_ip = lease4["ip-address"]
    ip = nb_api.ipam.ip_addresses.create(address=f"{lease_ip}/24")
    yield lease_ip
    ip.delete()


@pytest.fixture
def leases6_250(kea: KeaClient) -> None:
    for i in range(1, 251):
        kea.command(
            "lease6-add",
            service=["dhcp6"],
            arguments={
                "ip-address": f"2001:db8:1::{i:x}",
                "duid": str(EUI(i * 10, dialect=mac_unix_expanded)),
                "hw-address": str(EUI(i, dialect=mac_unix_expanded)),
                "iaid": i,
                "valid-lft": 3600,
                "hostname": f"test-lease6-{i}",
                "preferred-lft": 7200,
            },
        )


@pytest.fixture
def leases4_250(kea: KeaClient) -> None:
    for i in range(1, 251):
        kea.command(
            "lease4-add",
            service=["dhcp4"],
            arguments={
                "ip-address": f"192.0.2.{i}",
                "client-id": str(EUI(i * 10, dialect=mac_unix_expanded)),
                "hw-address": str(EUI(i, dialect=mac_unix_expanded)),
                "hostname": f"test-lease4-{i}",
            },
        )


@pytest.fixture(scope="function")
def netbox_user_permissions() -> list[dict[str, list[Any]]]:
    return [{"actions": [], "object_types": []}]


@pytest.fixture(scope="function", autouse=True)
def netbox_login(
    page: Page,
    netbox_url: str,
    netbox_username: str,
    netbox_password: str,
    netbox_user_permissions: list[dict[str, list[Any]]],
    nb_api: pynetbox.api,
):
    to_delete = []
    if netbox_username != "admin":
        nb_api.users.users.filter(username=netbox_username).delete()
        nb_api.users.permissions.all(0).delete()
        user = nb_api.users.users.create(
            username=netbox_username, password=netbox_password
        )
        to_delete.append(user)
        for permission in netbox_user_permissions:
            p = nb_api.users.permissions.create(
                name=netbox_username,
                actions=permission["actions"],
                object_types=permission["object_types"],
                users=[user.id],
            )
            to_delete.append(p)

    page.goto(f"{netbox_url}/login/")
    page.get_by_label("Username").fill(netbox_username)
    page.get_by_label("Password").fill(netbox_password)
    page.get_by_role("button", name="Sign In").click()

    yield

    for obj in to_delete:
        assert obj.delete()


@pytest.fixture(scope="session")
def test_tag(nb_api: pynetbox.api):
    tag = nb_api.extras.tags.create(name="kea-test", slug="kea-test")
    assert tag is not None
    yield tag.name
    tag.delete()


@pytest.fixture(scope="session")
def test_site(nb_api: pynetbox.api):
    site = nb_api.dcim.sites.create(name="Test Site", slug="test-site")
    yield site.id
    site.delete()


@pytest.fixture(scope="session")
def test_device_type(nb_api: pynetbox.api):
    manufacturer = nb_api.dcim.manufacturers.create(
        name="Test Manufacturer", slug="test-manufacturer"
    )
    device_type = nb_api.dcim.device_types.create(
        manufacturer=manufacturer.id,
        model="test model",
        slug="test-model",
    )
    yield device_type.id
    device_type.delete()
    manufacturer.delete()


@pytest.fixture(scope="session")
def test_device_role(nb_api: pynetbox.api):
    role = nb_api.dcim.device_roles.create(name="Test Role", slug="test-role")
    yield role.id
    role.delete()


@pytest.fixture(scope="session")
def test_cluster(nb_api: pynetbox.api):
    cluster_type = nb_api.virtualization.cluster_types.create(
        name="test cluster type",
        slug="test-cluster-type",
    )
    cluster = nb_api.virtualization.clusters.create(
        name="Test Cluster", type=cluster_type.id
    )
    yield cluster.id
    cluster.delete()
    cluster_type.delete()


def search_lease(page: Page, version: Literal[4, 6], by: str, q: str) -> None:
    page.get_by_role("link", name=f"DHCPv{version} Leases").click()
    page.locator("#id_q").fill(q)
    page.locator("#id_by + div.form-select").click()
    page.locator("#id_by-ts-dropdown").get_by_role(
        "option", name=by, exact=True
    ).click()
    with page.expect_response(re.compile(f"/leases{version}/")) as r:
        page.get_by_role("button", name="Search").click()
        assert r.value.ok


def search_lease_related(page: Page, model: str) -> None:
    page.locator("span.dropdown > a.btn-secondary").click()
    page.get_by_role("link", name=f"Search {model}").click()
    expect(page.get_by_text("Showing 1-1 of 1")).to_have_count(1)


def expect_form_error_search(page: Page, b: bool) -> None:
    expect(page.locator("#id_q + div.form-text.text-danger")).to_have_count(int(b))


def configure_table(page: Page, *selected_coumns: str) -> None:
    page.get_by_role("button", name=re.compile("Configure Table")).click()

    # Clear all selected columns
    remove_button = page.get_by_text("Remove")
    selected_count = page.locator("#id_columns > option").count()
    for i in range(selected_count):
        page.locator("#id_columns > option").first.click()
        remove_button.click()

    for sc in selected_coumns:
        page.locator(f'#id_available_columns > option[value="{sc}"]').click()
        page.get_by_text("Add", exact=True).click()

    page.get_by_role("button", name="Save").click()


@pytest.mark.parametrize(
    ("netbox_username", "netbox_password", "netbox_user_permissions"),
    [
        ("admin", "admin", None),
        (
            "user",
            "user12Characters",
            [{"actions": ["view"], "object_types": ["netbox_kea.server"]}],
        ),
    ],
)
def test_navigation_view(page: Page) -> None:
    page.get_by_role("button", name="󰐱 Plugins").click()
    page.get_by_role("link", name="Servers").click()

    expect(page).to_have_title(re.compile("^Servers.*"))


@pytest.mark.parametrize(
    ("netbox_username", "netbox_password", "netbox_user_permissions"),
    [
        ("admin", "admin", None),
        (
            "user",
            "user12Characters",
            [{"actions": ["view", "add"], "object_types": ["netbox_kea.server"]}],
        ),
    ],
)
def test_navigation_add(page: Page) -> None:
    page.get_by_role("button", name="󰐱 Plugins").click()
    page.get_by_role("link", name="Servers").hover()
    page.get_by_role("link", name="󱇬", exact=True).click()

    expect(page).to_have_title(re.compile("^Add a new server.*"))


@pytest.mark.parametrize(
    ("netbox_username", "netbox_password", "netbox_user_permissions"),
    [
        (
            "user",
            "user12Characters",
            [],
        ),
    ],
)
def test_navigation_view_no_access(page: Page) -> None:
    expect(page.get_by_role("button", name="󰐱 Plugins")).to_have_count(0)


@pytest.mark.parametrize(
    ("netbox_username", "netbox_password", "netbox_user_permissions"),
    [
        (
            "user",
            "user12Characters",
            [{"actions": ["view"], "object_types": ["netbox_kea.server"]}],
        ),
    ],
)
def test_navigation_add_no_access(page: Page) -> None:
    page.get_by_role("button", name="󰐱 Plugins").click()
    page.get_by_role("link", name="Servers").hover()
    expect(page.get_by_role("link", name="󱇬", exact=True)).to_have_count(0)


def test_server_add_delete(
    page: Page, plugin_base: str, kea_url: str, nb_api: pynetbox.api
) -> None:
    server_name = "test_server"
    page.goto(f"{plugin_base}/servers/add/")
    expect(page).to_have_title(re.compile("^Add a new server.*"))

    page.get_by_label("Name", exact=True).fill(server_name)
    page.get_by_label("Server URL", exact=True).fill(kea_url)
    page.get_by_role("button", name="Create", exact=True).click()

    expect(page).to_have_title(re.compile(f"^{server_name}"))
    server = nb_api.plugins.kea.servers.get(name=server_name)
    assert server is not None

    page.get_by_role("link", name="Delete").click()
    page.get_by_role("button", name="Delete").click()  # Confirm dialog

    server = nb_api.plugins.kea.servers.get(name=server_name)
    assert server is None


def test_server_bulk_delete(
    page: Page, plugin_base: str, nb_api: pynetbox.api, kea_url: str
):
    nb_api.plugins.kea.servers.create(
        [
            {"name": "server1", "server_url": kea_url},
            {"name": "server2", "server_url": kea_url},
        ]
    )

    page.goto(f"{plugin_base}/servers/")
    page.get_by_role("checkbox", name="Toggle All").click()
    page.get_by_role("button", name="Delete Selected").click()
    page.locator('button.btn-danger[type="submit"]').click()

    assert nb_api.plugins.kea.servers.count() == 0


def test_server_edit(page: Page, kea: KeaClient) -> None:
    new_name = "a_new_name"
    page.get_by_role("button", name="Edit").click()
    page.get_by_label("Name", exact=True).fill(new_name)
    page.get_by_role("button", name="Save").click()
    expect(page).to_have_title(re.compile(f"^{new_name}"))


def test_server_status(page: Page, kea: KeaClient) -> None:
    page.get_by_role("link", name="Status").click()

    ctrl_version = kea.command("version-get")[0]["arguments"]["extended"]
    dhcp4_version = kea.command("version-get", service=["dhcp4"])[0]["arguments"][
        "extended"
    ]
    dhcp6_version = kea.command("version-get", service=["dhcp6"])[0]["arguments"][
        "extended"
    ]

    locator = page.locator(".tab-content")
    expect(locator).to_contain_text(ctrl_version)
    expect(locator).to_contain_text(dhcp4_version)
    expect(locator).to_contain_text(dhcp6_version)


@pytest.mark.parametrize(
    ("family", "subnets"),
    (
        (
            4,
            (
                (1, "192.0.2.0/24", None),
                (2, "198.51.100.0/24", "test-shared-network-4"),
            ),
        ),
        (
            6,
            (
                (1, "2001:db8:1::/64", None),
                (2, "2001:db8:2::/64", "test-shared-network-6"),
            ),
        ),
    ),
)
def test_dhcp_subnets(
    page: Page,
    kea: KeaClient,
    family: str,
    subnets: Sequence[tuple[str, str, Optional[str]]],
) -> None:
    for i, (subnet_id, subnet, shared_network) in enumerate(subnets):
        page.get_by_role("link", name=f"DHCPv{family} Subnets").click()
        configure_table(page, "id", "subnet", "shared_network")
        rows = page.locator("table > tbody > tr")
        tds = rows.nth(i).locator("td")

        # Check column data
        # 0: ID
        # 1: Subnet
        # 2: Shared Network
        expect(tds.nth(0)).to_contain_text(str(subnet_id))
        expect(tds.nth(1)).to_contain_text(subnet)
        expect(tds.nth(2)).to_contain_text(shared_network or "—")

        with page.expect_response(re.compile(f"/leases{family}/")) as r:
            page.get_by_role("link", name=subnet).click()
            assert r.value.ok
        expect(page.locator("#id_q")).to_have_value(subnet)
        expect(
            page.locator("#id_by + div.form-select > div.ts-control > div.item")
        ).to_have_text("Subnet")


@pytest.mark.parametrize(
    ("family", "all_data", "expected_data"),
    (
        (
            4,
            True,
            [
                {"ID": str(1), "Subnet": "192.0.2.0/24", "Shared Network": ""},
                {
                    "ID": str(2),
                    "Subnet": "198.51.100.0/24",
                    "Shared Network": "test-shared-network-4",
                },
            ],
        ),
        (
            4,
            False,
            [
                {"ID": str(1), "Subnet": "192.0.2.0/24"},
                {"ID": str(2), "Subnet": "198.51.100.0/24"},
            ],
        ),
        (
            6,
            True,
            [
                {"ID": str(1), "Subnet": "2001:db8:1::/64", "Shared Network": ""},
                {
                    "ID": str(2),
                    "Subnet": "2001:db8:2::/64",
                    "Shared Network": "test-shared-network-6",
                },
            ],
        ),
        (
            6,
            False,
            [
                {"ID": str(1), "Subnet": "2001:db8:1::/64"},
                {"ID": str(2), "Subnet": "2001:db8:2::/64"},
            ],
        ),
    ),
)
def test_dhcp_subnets_export_csv(
    page: Page, kea: KeaClient, family: int, all_data: bool, expected_data: bool
) -> None:
    page.get_by_role("link", name=f"DHCPv{family} Subnets").click()

    if all_data is False:
        configure_table(page, "id", "subnet")

    page.get_by_role("button", name="Export").click()
    with page.expect_download() as dl:
        page.get_by_role(
            "link", name="All Data (CSV)" if all_data is True else "Current View"
        ).click()
    dl = dl.value
    assert dl.suggested_filename.endswith(".csv")

    with open(dl.path()) as f:
        r = csv.DictReader(f)
        have_rows = sorted(r, key=lambda x: x["ID"])
        assert have_rows == expected_data


@pytest.mark.parametrize("family", (4, 6))
def test_dhcp_subnets_configure_table(page: Page, kea: KeaClient, family: int) -> None:
    page.get_by_role("link", name=f"DHCPv{family} Subnets").click()

    configure_table(page, "subnet")
    expect(page.locator(".object-list > thead > tr > th > a")).to_have_text(
        ["Subnet", ""]
    )

    configure_table(page, "subnet", "shared_network")
    expect(page.locator(".object-list > thead > tr > th > a")).to_have_text(
        ["Subnet", "Shared Network", ""]
    )


@pytest.mark.parametrize(
    ("version", "by", "q"),
    (
        (6, "IP Address", "192.0.2.0"),
        (6, "IP Address", "192.0.2.0/24"),
        (6, "IP Address", "2001:db8::/64"),
        (6, "Subnet", "abc"),
        (6, "Subnet", "2001:db8::"),
        (6, "Subnet", "2001:db8::10/64"),
        (6, "Subnet", "192.0.2.0"),
        (6, "Subnet", "192.0.2.0/24"),
        (6, "Subnet ID", "foo"),
        (6, "Subnet ID", "192.0.2.0/24"),
        (6, "Subnet ID", "2001:db8::/64"),
        (6, "DUID", "foo"),
        (6, "DUID", "192.0.2.0"),
        (6, "DUID", "2001:db8::"),
        (6, "DUID", "0"),  # Too short
        (6, "DUID", "00" * (constants.DUID_MAX_OCTETS + 1)),
        (4, "IP Address", "2001:db8::"),
        (4, "IP Address", "2001:db8::/64"),
        (4, "IP Address", "192.0.2.0/24"),
        (4, "Hardware Address", "foo"),
        (4, "Hardware Address", "192.0.2.0"),
        (4, "Hardware Address", "2001:db8::"),
        (4, "Client ID", "foo"),
        (4, "Client ID", "192.0.2.0"),
        (4, "Client ID", "2001:db8::"),
        (4, "Client ID", "0"),
        (4, "Client ID", "00" * (constants.CLIENT_ID_MAX_OCTETS + 1)),
        (4, "Subnet", "abc"),
        (4, "Subnet", "2001:db8::"),
        (4, "Subnet", "192.0.2.0"),
        (4, "Subnet", "192.0.2.10/24"),
        (4, "Subnet", "2001:db8::/64"),
        (4, "Subnet ID", "foo"),
        (4, "Subnet ID", "192.0.2.0/24"),
        (4, "Subnet ID", "2001:db8::/64"),
    ),
)
def test_dhcp_lease_invalid_search_values(
    page: Page, kea: KeaClient, version: int, by: str, q: str
) -> None:
    page.get_by_role("link", name=f"DHCPv{version} Leases").click()
    page.locator("#id_q").fill(q)
    page.locator("#id_by + div.form-select").click()
    page.locator("#id_by-ts-dropdown").get_by_role(
        "option", name=by, exact=True
    ).click()
    page.get_by_role("button", name="Search").click()
    expect_form_error_search(page, True)
    expect(page.locator("div.table-container")).to_have_count(0)


@pytest.mark.parametrize("family", (4, 6))
def test_dhcp_lease_all_columns(
    page: Page, kea: KeaClient, family: Literal[6, 4], request: pytest.FixtureRequest
) -> None:
    lease_args = request.getfixturevalue(f"lease{family}")
    lease_ip = lease_args["ip-address"]

    lease = kea.command(
        f"lease{family}-get",
        service=[f"dhcp{family}"],
        arguments={"ip-address": lease_ip},
    )[0]["arguments"]
    assert lease is not None

    search_lease(page, family, "IP Address", lease_ip)

    if family == 6:
        configure_table(
            page,
            "ip_address",
            "hostname",
            "hw_address",
            "cltt",
            "subnet_id",
            "valid_lft",
            "duid",
            "type",
            "preferred_lft",
            "expires_at",
            "expires_in",
            "iaid",
        )

        def check():
            cltt = datetime.fromtimestamp(lease["cltt"], timezone.utc)
            expect(page.locator("table.object-list > tbody > tr > td")).to_have_text(
                [
                    re.compile(".*"),  # select
                    lease["ip-address"],
                    lease["hostname"],
                    lease["hw-address"],
                    f"{cltt.date().isoformat()} {cltt.time().isoformat()}",
                    str(lease["subnet-id"]),
                    "01:00:00",
                    lease["duid"],
                    lease["type"],
                    "02:00:00",
                    re.compile(r"\d{4}-\d{2}-\d{2} \d{2}:\d{2}"),
                    re.compile(r"\d{2}:\d{2}:\d{2}"),
                    str(lease["iaid"]),
                    re.compile(".*"),  # actions
                ]
            )

    else:
        configure_table(
            page,
            "ip_address",
            "hostname",
            "hw_address",
            "cltt",
            "subnet_id",
            "valid_lft",
            "expires_at",
            "expires_in",
            "client_id",
        )

        def check():
            cltt = datetime.fromtimestamp(lease["cltt"], timezone.utc)
            expect(page.locator("table.object-list > tbody > tr > td")).to_have_text(
                [
                    "",  # select
                    lease["ip-address"],
                    lease["hostname"],
                    lease["hw-address"],
                    f"{cltt.date().isoformat()} {cltt.time().isoformat()}",
                    str(lease["subnet-id"]),
                    "01:00:00",
                    re.compile(r"\d{4}-\d{2}-\d{2} \d{2}:\d{2}"),
                    re.compile(r"\d{2}:\d{2}:\d{2}"),
                    lease["client-id"],
                    re.compile(".*"),  # actions
                ]
            )

    check()

    # Should be the same on reload
    page.reload()
    check()


@pytest.mark.parametrize(
    ("family", "all_data", "check_fields"),
    (
        (
            6,
            True,
            (
                ("IP Address", "ip-address"),
                ("Hardware Address", "hw-address"),
                ("DUID", "duid"),
                ("IAID", "iaid"),
            ),
        ),
        (
            6,
            False,
            (
                ("IP Address", "ip-address"),
                ("Hostname", "hostname"),
                ("Subnet ID", "subnet-id"),
            ),
        ),
        (
            4,
            True,
            (
                ("IP Address", "ip-address"),
                ("Hardware Address", "hw-address"),
                ("Client ID", "client-id"),
                ("Hostname", "hostname"),
            ),
        ),
        (
            4,
            False,
            (
                ("IP Address", "ip-address"),
                ("Hostname", "hostname"),
                ("Subnet ID", "subnet-id"),
            ),
        ),
    ),
)
def test_dhcp_export_csv_all(
    page: Page,
    kea: KeaClient,
    family: Literal[4, 6],
    all_data: bool,
    check_fields: tuple[tuple[str, str], ...],
    request: pytest.FixtureRequest,
):
    request.getfixturevalue(f"leases{family}_250")

    leases = kea.command(f"lease{family}-get-all", service=[f"dhcp{family}"])[0][
        "arguments"
    ]["leases"]

    search_lease(
        page, family, "Subnet", "2001:db8:1::/64" if family == 6 else "192.0.2.0/24"
    )
    configure_table(page, "ip_address", "hostname", "subnet_id")

    page.get_by_role("button", name="Export").click()
    with page.expect_download() as dl:
        page.get_by_role(
            "link", name="All Data (CSV)" if all_data is True else "Current View"
        ).click()
    dl = dl.value
    assert dl.suggested_filename.endswith(".csv")

    with open(dl.path()) as f:
        r = csv.DictReader(f)
        have_rows = sorted(r, key=lambda x: x["IP Address"])

    want_rows = sorted(leases, key=lambda x: x["ip-address"])

    assert len(have_rows) == len(want_rows)
    for have_dict, want_dict in zip(have_rows, want_rows):
        for have_key, want_key in check_fields:
            assert have_dict[have_key] == str(want_dict[want_key])


@pytest.mark.parametrize("family", (6, 4))
def test_lease_delete(
    page: Page,
    kea: KeaClient,
    family: Literal[6, 4],
    request: pytest.FixtureRequest,
) -> None:
    ip = request.getfixturevalue(f"lease{family}")["ip-address"]

    search_lease(page, family, "IP Address", ip)

    expect(page.locator(".object-list > tbody > tr")).to_have_count(1)
    page.locator('input[name="pk"]').check()

    url = page.url

    page.get_by_role("button", name="Delete Selected").click()
    page.locator('button[name="_confirm"]').click()
    expect(page.locator(".toast-body")).to_have_text(
        re.compile(f"Deleted 1 DHCPv{family} lease\\(s\\)")
    )

    kea.command(
        f"lease{family}-get",
        service=[f"dhcp{family}"],
        arguments={"ip-address": ip},
        check=(3,),
    )

    expect(page).to_have_url(url)


@pytest.mark.parametrize(
    ("netbox_username", "netbox_password", "netbox_user_permissions"),
    [
        (
            "delete-user",
            "delete-user12Characters",
            [
                {
                    "actions": ["view", "bulk_delete_lease_from"],
                    "object_types": ["netbox_kea.server"],
                }
            ],
        ),
        (
            "no-delete-user",
            "no-delete-user12Characters",
            [{"actions": ["view"], "object_types": ["netbox_kea.server"]}],
        ),
    ],
)
@pytest.mark.parametrize("family", (6, 4))
def test_lease_delete_no_permission(
    page: Page,
    kea: KeaClient,
    netbox_username: str,
    family: Literal[6, 4],
    request: pytest.FixtureRequest,
) -> None:
    ip = request.getfixturevalue(f"lease{family}")["ip-address"]

    search_lease(page, family, "IP Address", ip)

    expected_count = int(netbox_username.startswith("delete"))

    expect(page.locator(".object-list > tbody > tr")).to_have_count(1)

    expect(page.locator('input[name="pk"]')).to_have_count(expected_count)
    expect(page.get_by_role("button", name="Delete Selected")).to_have_count(
        expected_count
    )


@pytest.mark.parametrize(
    ("netbox_username", "netbox_password", "netbox_user_permissions"),
    [
        (
            "delete-user",
            "delete-user12Characters",
            [
                {
                    "actions": ["view", "bulk_delete_lease_from"],
                    "object_types": ["netbox_kea.server"],
                }
            ],
        ),
    ],
)
@pytest.mark.parametrize("family", (6, 4))
def test_lease_delete_no_permission_on_confirm(
    page: Page,
    kea: KeaClient,
    nb_api: pynetbox.api,
    netbox_username: str,
    family: Literal[6, 4],
    request: pytest.FixtureRequest,
) -> None:
    ip = request.getfixturevalue(f"lease{family}")["ip-address"]

    search_lease(page, family, "IP Address", ip)

    expect(page.locator(".object-list > tbody > tr")).to_have_count(1)
    page.locator('input[name="pk"]').check()

    page.get_by_role("button", name="Delete Selected").click()

    # Remove bulk_delete_lease_from permission from the user before confirming
    user = nb_api.users.users.get(username=netbox_username)
    assert user is not None
    assert len(user.permissions) == 1
    p = user.permissions[0]
    p.actions = ["view"]
    assert p.save()

    page.locator('button[name="_confirm"]').click()
    expect(page.locator("body")).to_have_text(
        "This user does not have permission to delete DHCP leases."
    )


@pytest.mark.parametrize("family", (6, 4))
def test_lease_deleted_before_delete(
    page: Page,
    kea: KeaClient,
    family: Literal[6, 4],
    request: pytest.FixtureRequest,
) -> None:
    ip = request.getfixturevalue(f"lease{family}")["ip-address"]

    search_lease(page, family, "IP Address", ip)

    expect(page.locator(".object-list > tbody > tr")).to_have_count(1)
    page.locator('input[name="pk"]').check()
    page.get_by_role("button", name="Delete Selected").click()

    kea.command(
        f"lease{family}-del", service=[f"dhcp{family}"], arguments={"ip-address": ip}
    )

    page.locator('button[name="_confirm"]').click()
    # Kea will return status 3
    expect(page.locator(".toast-body")).to_have_text(
        re.compile(f"Deleted 1 DHCPv{family} lease\\(s\\)")
    )


@pytest.mark.parametrize("family", (6, 4))
def test_lease_deleted_invalid_ip(
    page: Page,
    kea: KeaClient,
    family: Literal[6, 4],
    request: pytest.FixtureRequest,
) -> None:
    ip = request.getfixturevalue(f"lease{family}")["ip-address"]

    search_lease(page, family, "IP Address", ip)

    expect(page.locator(".object-list > tbody > tr")).to_have_count(1)
    pk = page.locator('input[name="pk"]')
    pk.evaluate('node => node.value = "notanip"')
    pk.check()
    page.get_by_role("button", name="Delete Selected").click()
    expect(page.locator(".toast-body")).to_contain_text("Invalid IP")


@pytest.mark.parametrize("family", (6, 4))
def test_lease_deleted_invalid_ip_confirm(
    page: Page,
    kea: KeaClient,
    family: Literal[6, 4],
    request: pytest.FixtureRequest,
) -> None:
    ip = request.getfixturevalue(f"lease{family}")["ip-address"]

    search_lease(page, family, "IP Address", ip)

    expect(page.locator(".object-list > tbody > tr")).to_have_count(1)
    page.locator('input[name="pk"]').check()
    page.get_by_role("button", name="Delete Selected").click()
    page.locator("#id_pk_0").evaluate('node => node.value = "notanip"')
    page.locator('button[name="_confirm"]').click()

    expect(page.locator(".toast-body")).to_contain_text("Invalid IP")


@pytest.mark.parametrize(
    ("family", "search_by", "search_value_attr"),
    (
        (6, "IP Address", "ip-address"),
        (6, "Hostname", "hostname"),
        (6, "DUID", "duid"),
        (6, "Subnet ID", "subnet-id"),
        (4, "IP Address", "ip-address"),
        (4, "Hostname", "hostname"),
        (4, "Hardware Address", "hw-address"),
        (4, "Client ID", "client-id"),
        (4, "Subnet ID", "subnet-id"),
    ),
)
def test_lease_search(
    page: Page,
    family: Literal[6, 4],
    search_by: str,
    search_value_attr: str,
    request: pytest.FixtureRequest,
) -> None:
    lease = request.getfixturevalue(f"lease{family}")
    search_lease(page, family, search_by, str(lease[search_value_attr]))
    expect_form_error_search(page, False)
    expect(page.locator(".object-list > tbody > tr")).to_have_count(1)
    expect(page.locator(".object-list > tbody > tr > td").nth(1)).to_have_text(
        lease["ip-address"]
    )


@pytest.mark.parametrize("sep", ("-", ""))
@pytest.mark.parametrize(
    ("family", "search_by", "search_value_attr"),
    (
        (6, "DUID", "duid"),
        (4, "Hardware Address", "hw-address"),
        (4, "Client ID", "client-id"),
    ),
)
def test_lease_search_eui_formats(
    page: Page,
    family: Literal[6, 4],
    search_by: str,
    search_value_attr: str,
    sep: str,
    request: pytest.FixtureRequest,
) -> None:
    lease = request.getfixturevalue(f"lease{family}")
    search_lease(page, family, search_by, lease[search_value_attr].replace(":", sep))
    expect(page.locator(".object-list > tbody > tr")).to_have_count(1)
    expect(page.locator(".object-list > tbody > tr > td").nth(1)).to_have_text(
        lease["ip-address"]
    )


def test_lease_search_cisco_style_mac(page: Page, lease4: dict[str, Any]) -> None:
    mac = lease4["hw-address"].replace(":", "")
    cisco_mac = f"{mac[:4]}.{mac[4:8]}.{mac[8:]}"
    search_lease(page, 4, "Hardware Address", cisco_mac)
    expect(page.locator(".object-list > tbody > tr")).to_have_count(1)
    expect(page.locator(".object-list > tbody > tr > td").nth(1)).to_have_text(
        lease4["ip-address"]
    )


@pytest.mark.parametrize(
    "prefix",
    (
        "2001:db8:1::/124",
        "2001:db8:1::10/124",
        "2001:db8:1::/121",
        "2001:db8:1::/64",
        "::/0",
        "192.0.2.0/29",
        "192.0.2.8/29",
        "192.0.2.0/25",
        "192.0.2.0/24",
        "0.0.0.0/0",
    ),
)
def test_lease_search_by_subnet(
    page: Page,
    prefix: str,
    request: pytest.FixtureRequest,
) -> None:
    # per page default is 50
    per_page = 50

    net = IPNetwork(prefix)
    family = net.version
    dhcp_scope = (
        IPNetwork("2001:db8:1::/64") if family == 6 else IPNetwork("192.0.2.0/24")
    )
    skip_first = dhcp_scope.network in net
    lease_count = min(net.size - int(skip_first), 250)
    request.getfixturevalue(f"leases{family}_250")

    search_lease(page, family, "Subnet", str(net))

    def check_count(count: int) -> None:
        expect(page.locator(".object-list > tbody > tr")).to_have_count(count)

    first_ip = max(net[int(skip_first)], dhcp_scope[1])

    def click_next() -> None:
        with page.expect_response(re.compile(f"/leases{family}/")) as r:
            page.get_by_role("button", name="Next").click()
            assert r.value.ok

    def check_first_row_ip(ip: IPAddress) -> None:
        expect(page.locator(".object-list > tbody > tr > td").nth(1)).to_have_text(
            str(ip)
        )

    check_first_row_ip(first_ip)
    check_count(min(lease_count, per_page))

    for _ in range(int(lease_count / per_page) - 1):
        # Kea doesn't guarantee order...
        first_ip += per_page
        click_next()
        check_first_row_ip(first_ip)
        check_count(per_page)

    if net.size > per_page:
        first_ip += per_page
        click_next()
        if first_ip != dhcp_scope.network + 251:
            check_first_row_ip(first_ip)
            check_count(lease_count % per_page)
        else:
            expect(page.locator(".object-list > tbody > tr > td")).to_have_text(
                "— No leases found. —"
            )

    expect(page.get_by_role("button", name="Next")).to_be_disabled()


@pytest.mark.parametrize(
    ("family", "subnet_page"),
    ((6, "abc"), (6, "2001:db8:2::"), (4, "abc"), (4, "192.0.3.0")),
)
def test_lease_search_by_subnet_invalid_page(
    page: Page,
    kea: KeaClient,
    plugin_base: str,
    family: Literal[6, 4],
    subnet_page: str,
) -> None:
    prefix = "2001:db8:1::/64" if family == 6 else "192.0.2.0/24"
    page.goto(f"{page.url}/leases{family}/?q={prefix}&by=subnet&page={subnet_page}")
    expect(page.locator("#lease-search").get_by_role("alert")).to_have_count(1)


@pytest.mark.parametrize(
    ("family", "by", "q"),
    (
        (6, "IP Address", "2001:db8::"),
        (6, "Subnet ID", "1"),
        (6, "Hostname", "foo"),
        (6, "DUID", "01:02:03:04:05:06:07:08"),
        (4, "IP Address", "192.0.2.0"),
        (4, "Subnet ID", "1"),
        (4, "Hardware Address", "08:08:08:08:08:08"),
        (4, "Client ID", "18:08:08:08:08:08"),
        (4, "Hostname", "foo"),
    ),
)
def test_lease_search_page_param_without_subnet(
    page: Page, kea: KeaClient, family: Literal[4, 6], by: str, q: str
) -> None:
    search_lease(page, family, by, q)
    expect(page).to_have_url(re.compile("by="))
    page_param = "2001:db8:1::" if family == 6 else "192.0.2.0"
    page.goto(f"{page.url}&page={page_param}")
    expect(page.locator("form.form").get_by_role("alert")).to_contain_text(
        "page is only supported with subnet."
    )


def test_filter_servers_by_tag(
    nb_api: pynetbox.api,
    test_tag: str,
    kea_url: str,
    plugin_base: str,
    page: Page,
) -> None:
    nb_api.plugins.kea.servers.create(
        name="tag-test", server_url=kea_url, tags=[{"name": test_tag}]
    )

    page.goto(f"{plugin_base}/servers/")
    page.get_by_role("tab", name="Filters").click()
    page.locator("#id_tag + div.form-select").click()
    page.locator("#id_tag-ts-dropdown").get_by_role(
        "option", name=f"{test_tag} (1)"
    ).click()
    page.get_by_role("button", name=re.compile("Search")).click()
    expect(page.get_by_text("Showing 1-1 of 1")).to_have_count(1)


@pytest.mark.parametrize("version", (6, 4))
def test_one_service_only(
    page: Page, version: Literal[6, 4], request: pytest.FixtureRequest
) -> None:
    request.getfixturevalue(f"with_test_server_only{version}")

    server_url = page.url
    pages4 = int(version == 4)
    pages6 = int(version == 6)
    expect(page.get_by_role("link", name="DHCPv4 Leases")).to_have_count(pages4)
    expect(page.get_by_role("link", name="DHCPv4 Subnets")).to_have_count(pages4)
    expect(page.get_by_role("link", name="DHCPv6 Leases")).to_have_count(pages6)
    expect(page.get_by_role("link", name="DHCPv6 Subnets")).to_have_count(pages6)

    page.goto(f"{server_url}/leases6/")
    if version == 4:
        expect(page).to_have_url(server_url)
    else:
        expect(page).not_to_have_url(server_url)

    page.goto(f"{server_url}/leases4/")
    if version == 6:
        expect(page).to_have_url(server_url)
    else:
        expect(page).not_to_have_url(server_url)


@pytest.mark.parametrize("version", (6, 4))
def test_lease_to_ip(
    page: Page,
    with_test_server: None,
    request: pytest.FixtureRequest,
    version: Literal[6, 4],
) -> None:
    lease_ip: str = request.getfixturevalue(f"lease{version}_netbox_ip")

    search_lease(page, version, "IP Address", lease_ip)
    search_lease_related(page, "IPs")


@pytest.mark.parametrize("version", (6, 4))
def test_lease_to_device(
    page: Page,
    with_test_server: None,
    request: pytest.FixtureRequest,
    version: Literal[6, 4],
) -> None:
    lease_ip: str = request.getfixturevalue(f"lease{version}_netbox_device")

    server_url = page.url

    search_lease(page, version, "IP Address", lease_ip)
    search_lease_related(page, "devices")

    page.goto(server_url)
    search_lease(page, version, "IP Address", lease_ip)
    search_lease_related(page, "interfaces")


@pytest.mark.parametrize("version", (6, 4))
def test_lease_to_vm(
    page: Page,
    with_test_server: None,
    request: pytest.FixtureRequest,
    version: Literal[6, 4],
) -> None:
    lease_ip: str = request.getfixturevalue(f"lease{version}_netbox_vm")

    server_url = page.url

    search_lease(page, version, "IP Address", lease_ip)
    search_lease_related(page, "VMs")

    page.goto(server_url)
    search_lease(page, version, "IP Address", lease_ip)
    search_lease_related(page, "VM interfaces")


@pytest.mark.parametrize("placement", ("top", "bottom", "both"))
@pytest.mark.parametrize("version", (6, 4))
def test_lease_pagination_location(
    page: Page,
    requests_session: requests.Session,
    nb_api: pynetbox.api,
    with_test_server: None,
    request: pytest.FixtureRequest,
    version: Literal[6, 4],
    placement: Literal["top", "bottom", "both"],
) -> None:
    placement = "bottom"
    lease_args = request.getfixturevalue(f"lease{version}")
    ip = lease_args["ip-address"]

    # pynetbox doesn't support this endpoint
    requests_session.patch(
        url=f"{nb_api.base_url}/users/config/",
        json={"pagination": {"placement": placement}},
    ).raise_for_status()

    search_lease(page, version, "IP Address", ip)

    counts = page.get_by_text(re.compile(r"^Showing \d+ lease\(s\)$"))

    if placement == "both":
        expect(counts).to_have_count(2)
        count_y_top = counts.nth(0).bounding_box()["y"]
        count_y_bottom = counts.nth(0).bounding_box()["y"]
        table_y = page.get_by_role("link", name="IP Address").bounding_box()["y"]

        assert count_y_top < table_y
        assert count_y_bottom > table_y
    else:
        expect(counts).to_have_count(1)
        count_y = page.get_by_text(
            re.compile(r"^Showing \d+ lease\(s\)$")
        ).bounding_box()["y"]
        table_y = page.get_by_role("link", name="IP Address").bounding_box()["y"]

        match placement:
            case "top":
                assert count_y < table_y
            case "bottom":
                assert count_y > table_y
            case _:
                assert False
