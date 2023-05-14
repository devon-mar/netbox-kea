import csv
import re
from datetime import datetime
from typing import Any, Dict, Literal, Sequence, Tuple

import pynetbox
import pytest
import requests
from netaddr import EUI, IPAddress, IPNetwork, mac_unix_expanded
from playwright.sync_api import Page, expect

from . import constants

# This is linked from netbox_kea to avoid import errors
from .kea import KeaClient


@pytest.fixture(autouse=True)
def clear_leases(kea_client: KeaClient) -> None:
    kea_client.command("lease4-wipe", service=["dhcp4"], check=(0, 3))
    kea_client.command("lease6-wipe", service=["dhcp6"], check=(0, 3))


@pytest.fixture(autouse=True)
def reset_user_config_tables(nb_api: pynetbox.api) -> None:
    s = requests.Session()
    s.headers.update(
        {
            "Authorization": f"Token {nb_api.token}",
            "Content-Type": "application/json",
            "Accept": "application/json",
        }
    )
    r = s.get(url=f"{nb_api.base_url}/users/config/")
    r.raise_for_status()
    tables_config = r.json().get("tables", {})

    # pynetbox doesn't support this endpoint
    s.patch(
        url=f"{nb_api.base_url}/users/config/",
        json={"tables": {k: {} for k in tables_config}},
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
def kea_client() -> KeaClient:
    return KeaClient("http://localhost:8001")


@pytest.fixture
def kea(with_test_server: None, kea_client: KeaClient) -> KeaClient:
    return kea_client


@pytest.fixture
def plugin_base(netbox_url: str) -> str:
    return f"{netbox_url}/plugins/kea/"


@pytest.fixture
def lease6(kea: KeaClient) -> Dict[str, Any]:
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
def lease4(kea: KeaClient) -> Dict[str, Any]:
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


@pytest.fixture(scope="function", autouse=True)
def netbox_login(
    page: Page, netbox_url: str, netbox_username: str, netbox_password: str
) -> None:
    page.goto(f"{netbox_url}/login")
    page.get_by_placeholder("Username").fill(netbox_username)
    page.get_by_placeholder("Password").fill(netbox_password)
    page.get_by_role("button", name="Sign In").click()


def search_lease(page: Page, version: Literal[4, 6], by: str, q: str) -> None:
    page.get_by_role("link", name=f"DHCPv{version} Leases").click()
    page.locator("#id_q").fill(q)
    page.locator("span.ss-deselect").click()
    page.locator("div.ss-main").click()
    page.get_by_role("option", name=by, exact=True).click()
    with page.expect_response(re.compile(f"/leases{version}/")) as r:
        page.get_by_role("button", name="Search").click()
        assert r.value.ok


def expect_form_error_search(page: Page, b: bool) -> None:
    expect(
        page.locator("form > div").nth(0).locator("div.col > div.text-danger")
    ).to_have_count(int(b))


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


def test_navigation(page: Page) -> None:
    page.locator('a[href="#menuPlugins"]').click()
    page.locator('a.nav-link[href="/plugins/kea/servers/"]').click()

    expect(page).to_have_title(re.compile("^Servers.*"))


def test_navigation_add(page: Page) -> None:
    page.locator('a[href="#menuPlugins"]').click()
    page.locator("#menuPlugins").get_by_title("Add").click()

    expect(page).to_have_title(re.compile("^Add a new server.*"))


def test_server_add_delete(
    page: Page, plugin_base: str, kea_url: str, nb_api: pynetbox.api
) -> None:
    server_name = "test_server"
    page.goto(f"{plugin_base}/servers/add/")
    expect(page).to_have_title(re.compile("^Add a new server.*"))

    page.get_by_placeholder("Name", exact=True).fill(server_name)
    page.get_by_placeholder("Server URL", exact=True).fill(kea_url)
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
    page.get_by_placeholder("Name", exact=True).fill(new_name)
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
        (4, ("192.0.2.0/24",)),
        (6, ("2001:db8:1::/64",)),
    ),
)
def test_dhcp_subnets(
    page: Page, kea: KeaClient, family: str, subnets: Sequence[str]
) -> None:
    page.get_by_role("link", name=f"DHCPv{family} Subnets").click()

    locator = page.locator(".tab-content")
    for s in subnets:
        expect(locator).to_contain_text(s)

    page.get_by_role("link", name=subnets[0]).click()
    expect(page).to_have_url(re.compile(f"q={subnets[0]}"))
    expect(page).to_have_url(re.compile("by=subnet"))
    expect(page).to_have_url(re.compile(f"/leases{family}/\\?"))


@pytest.mark.parametrize("family", (4, 6))
def test_dhcp_subnets_configure_table(page: Page, kea: KeaClient, family: int) -> None:
    page.get_by_role("link", name=f"DHCPv{family} Subnets").click()

    configure_table(page, "subnet")
    expect(page.locator(".object-list > thead > tr > th > a")).to_have_text(
        ["Subnet", ""]
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
    page.locator("span.ss-deselect").click()
    page.locator("div.ss-main").click()
    page.get_by_role("option", name=by, exact=True).click()
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
            "state",
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
            expect(page.locator(".object-list > tbody > tr > td")).to_have_text(
                [
                    re.compile(".*"),  # select
                    lease["ip-address"],
                    lease["hostname"],
                    lease["hw-address"],
                    datetime.utcfromtimestamp(lease["cltt"]).strftime("%Y-%m-%d %H:%M"),
                    str(lease["state"]),
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
            "state",
            "subnet_id",
            "valid_lft",
            "expires_at",
            "expires_in",
            "client_id",
        )

        def check():
            expect(page.locator(".object-list > tbody > tr > td")).to_have_text(
                [
                    "",  # select
                    lease["ip-address"],
                    lease["hostname"],
                    lease["hw-address"],
                    datetime.utcfromtimestamp(lease["cltt"]).strftime("%Y-%m-%d %H:%M"),
                    str(lease["state"]),
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
    check_fields: Tuple[Tuple[str, str], ...],
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


def test_lease_search_cisco_style_mac(page: Page, lease4: Dict[str, Any]) -> None:
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
                "No leases found."
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