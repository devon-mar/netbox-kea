import django_tables2 as tables
from django.urls import reverse
from django.utils.http import urlencode
from netbox.tables import BaseTable, BooleanColumn, NetBoxTable, ToggleColumn, columns

from netbox_kea.utilities import format_duration

from .models import Server

SUBNET_ACTIONS = """<span class="btn-group dropdown">
  <a class="btn btn-sm btn-secondary dropdown-toggle" href="#" type="button" data-bs-toggle="dropdown">
  <i class="mdi mdi-magnify"></i></a>
  <ul class="dropdown-menu">
    {% if record.pk %}
    <li>
      <a href="{% url "ipam:prefix" pk=record.pk %}" class="dropdown-item">
        <i class="mdi mdi-open-in-app" aria-hidden="true" title="View prefix"></i>
        View prefix
      </a>
    </li>
    {% endif %}
    {% if record.subnet %}
    <li>
      <a href="{% url "ipam:prefix_list" %}?prefix={{ record.subnet }}" class="dropdown-item">
        <i class="mdi mdi-magnify" aria-hidden="true" title="Search for prefix"></i>
        Search for prefix
      </a>
    </li>
    {% endif %}
  </ul>
</span>
"""  # noqa: E501


LEASE_ACTIONS = """<span class="btn-group dropdown">
    <a class="btn btn-sm btn-secondary dropdown-toggle" href="#" type="button" data-bs-toggle="dropdown">
    <i class="mdi mdi-magnify"></i></a>
    <ul class="dropdown-menu">
        {% if record.ip_address %}
        <li>
            <a href="{% url "ipam:ipaddress_list" %}?address={{ record.ip_address }}" class="dropdown-item">
                <i class="mdi mdi-magnify" aria-hidden="true" title="Search IPs"></i>
                Search IPs
            </a>
        </li>
        {% endif %}
        {% if record.hw_address %}
        <li>
            <a href="{% url "dcim:interface_list" %}?mac_address={{ record.hw_address }}" class="dropdown-item">
                <i class="mdi mdi-magnify" aria-hidden="true" title="Search interfaces"></i>
                Search interfaces
            </a>
        </li>
        <li>
            <a href="{% url "virtualization:vminterface_list" %}?mac_address={{ record.hw_address }}" class="dropdown-item">
                <i class="mdi mdi-magnify" aria-hidden="true" title="Search VM interfaces"></i>
                Search VM interfaces
            </a>
        </li>
        {% endif %}
        {% if record.hostname %}
        <li>
            <a href="{% url "dcim:device_list" %}?q={{ record.hostname }}" class="dropdown-item">
                <i class="mdi mdi-magnify" aria-hidden="true" title="Search devices"></i>
                Search devices
            </a>
        </li>
        <li>
            <a href="{% url "virtualization:virtualmachine_list" %}?q={{ record.hostname }}" class="dropdown-item">
                <i class="mdi mdi-magnify" aria-hidden="true" title="Search VMs"></i>
                Search VMs
            </a>
        </li>
        {% endif %}
    </ul>
</span>
"""  # noqa: E501


class DurationColumn(tables.Column):
    def render(self, value: int):
        """Value is in seconds."""
        return format_duration(value)


class ActionsColumn(tables.TemplateColumn):
    def __init__(self, template: str) -> None:
        super().__init__(
            template,
            attrs={"td": {"class": "text-end text-nowrap noprint"}},
            verbose_name="",
        )


class MonospaceColumn(tables.Column):
    def __init__(self, *args, additional_classes: list[str] | None = None, **kwargs):
        cls_str = "font-monospace"
        if additional_classes is not None:
            cls_str += " " + " ".join(additional_classes)
        super().__init__(*args, attrs={"td": {"class": cls_str}}, **kwargs)


class ServerTable(NetBoxTable):
    name = tables.Column(linkify=True)
    dhcp6 = BooleanColumn()
    dhcp4 = BooleanColumn()

    class Meta(NetBoxTable.Meta):
        model = Server
        fields = (
            "pk",
            "name",
            "server_url",
            "username",
            "password",
            "ssl_verify",
            "client_cert_path",
            "client_key_path",
            "ca_file_path",
            "dhcp6",
            "dhcp4",
        )
        default_columns = ("pk", "name", "server_url", "dhcp6", "dhcp4")


# we can't use NetBox table because it requires an actual model
class GenericTable(BaseTable):
    exempt_columns = ("actions", "pk")

    class Meta(BaseTable.Meta):
        empty_text = "No rows"
        fields: tuple[str, ...] = ()

    @property
    def objects_count(self):
        return len(self.data)


class SubnetTable(GenericTable):
    id = tables.Column(verbose_name="ID")
    subnet = tables.Column(
        linkify=lambda record, table: (
            (
                reverse(
                    f"plugins:netbox_kea:server_leases{record['dhcp_version']}",
                    args=[record["server_pk"]],
                )
                + "?"
                + urlencode({"by": "subnet", "q": record["subnet"]})
            )
            if record.get("subnet")
            else None
        ),
    )
    shared_network = tables.Column(verbose_name="Shared Network")
    actions = ActionsColumn(SUBNET_ACTIONS)

    class Meta(GenericTable.Meta):
        empty_text = "No subnets"
        fields = ("id", "subnet", "shared_network", "actions")
        default_columns = ("id", "subnet", "shared_network")


class BaseLeaseTable(GenericTable):
    # This column is for the select checkboxes.
    pk = ToggleColumn(verbose_name="IP Address", accessor="ip_address", visible=True)
    ip_address = tables.Column(verbose_name="IP Address")
    hostname = tables.Column(verbose_name="Hostname")
    subnet_id = tables.Column(verbose_name="Subnet ID")
    hw_address = MonospaceColumn(verbose_name="Hardware Address")
    valid_lft = DurationColumn(verbose_name="Valid Lifetime")
    cltt = columns.DateTimeColumn(verbose_name="Client Last Transaction Time")
    expires_at = columns.DateTimeColumn(verbose_name="Expires At")
    expires_in = DurationColumn(verbose_name="Expires In")
    actions = ActionsColumn(LEASE_ACTIONS)

    class Meta(GenericTable.Meta):
        empty_text = "No leases found."
        fields = (
            "ip_address",
            "hostname",
            "subnet_id",
            "hw_address",
            "valid_lft",
            "cltt",
            "expires_at",
            "expires_in",
            "actions",
        )
        default_columns = ("ip_address", "hostname")


class LeaseTable4(BaseLeaseTable):
    client_id = tables.Column(verbose_name="Client ID")

    class Meta(BaseLeaseTable.Meta):
        fields = ("client_id", *BaseLeaseTable.Meta.fields)


class LeaseTable6(BaseLeaseTable):
    type = tables.Column(verbose_name="Type", accessor="type")
    preferred_lft = DurationColumn(verbose_name="Preferred Lifetime")
    duid = MonospaceColumn(verbose_name="DUID", additional_classes=["text-break"])
    iaid = MonospaceColumn(verbose_name="IAID")

    class Meta(BaseLeaseTable.Meta):
        fields = ("type", "duid", "iaid", *BaseLeaseTable.Meta.fields)


class LeaseDeleteTable(GenericTable):
    ip_address = tables.Column(verbose_name="IP Address", accessor="ip")

    class Meta(NetBoxTable.Meta):
        empty_text = "No leases"
        fields = ("ip_address",)
        default_columns = ("ip_address",)
