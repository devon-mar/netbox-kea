import re
from collections.abc import Callable
from datetime import datetime
from typing import Any, Literal

from django.http import HttpResponse
from django.shortcuts import redirect
from django_tables2 import Table
from django_tables2.export import TableExport
from utilities.views import ViewTab

from . import constants
from .models import Server


def format_duration(s: int | None) -> str | None:
    if s is None:
        return None
    hours, rest = divmod(s, 3600)
    minutes, seconds = divmod(rest, 60)
    return f"{hours:02}:{minutes:02}:{seconds:02}"


def _enrich_lease(now: datetime, lease: dict[str, Any]) -> dict[str, Any]:
    """Add expires at and expires in to a lease."""

    # Need to replace "-" so we can access the values in a template
    lease = {k.replace("-", "_"): v for k, v in lease.items()}
    if "cltt" not in lease and "valid_lft" not in lease:
        return lease

    # https://kea.readthedocs.io/en/kea-2.2.0/arm/hooks.html?highlight=cltt#the-lease4-get-lease6-get-commands
    cltt = lease["cltt"]
    valid_lft = lease["valid_lft"]
    assert isinstance(cltt, int)
    assert isinstance(valid_lft, int)
    expires_at = datetime.fromtimestamp(cltt + valid_lft)
    lease["expires_at"] = expires_at
    lease["expires_in"] = (expires_at - now).seconds
    lease["cltt"] = datetime.fromtimestamp(cltt)
    return lease


def format_leases(leases: list[dict[str, Any]]) -> list[dict[str, Any]]:
    now = datetime.now()
    return [_enrich_lease(now, ls) for ls in leases]


def export_table(
    table: Table,
    filename: str,
    use_selected_columns: bool = False,
) -> HttpResponse:
    exclude_columns = {"pk", "actions"}

    if use_selected_columns:
        exclude_columns |= {name for name, _ in table.available_columns}

    exporter = TableExport(
        export_format=TableExport.CSV,
        table=table,
        exclude_columns=exclude_columns,
    )
    return exporter.response(filename=filename)


def is_hex_string(s: str, min_octets: int, max_octets: int):
    if not re.match(constants.HEX_STRING_REGEX, s):
        return False

    octets = len(s.replace(":", "").replace("-", "")) / 2
    return octets >= min_octets and octets <= max_octets


def check_dhcp_enabled(
    instance: Server, version: Literal[6, 4]
) -> HttpResponse | None:
    if (version == 6 and instance.dhcp6) or (version == 4 and instance.dhcp4):
        return None
    return redirect(instance.get_absolute_url())


class OptionalViewTab(ViewTab):
    def __init__(self, *args, is_enabled: Callable[[Any], bool], **kwargs) -> None:
        self.is_enabled = is_enabled
        super().__init__(*args, **kwargs)

    def render(self, instance):
        if self.is_enabled(instance):
            return super().render(instance)
        return None
