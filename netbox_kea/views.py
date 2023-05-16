import logging
from abc import ABCMeta
from typing import Any, Dict, List, Optional, Tuple

from django.contrib import messages
from django.http import HttpResponse
from django.http.request import HttpRequest
from django.shortcuts import redirect, render
from django.urls import reverse
from netaddr import IPAddress, IPNetwork
from netbox.views import generic
from utilities.exceptions import AbortRequest
from utilities.htmx import is_htmx
from utilities.paginator import EnhancedPaginator, get_paginate_count
from utilities.views import GetReturnURLMixin, ViewTab, register_model_view

from . import constants, forms, tables
from .filtersets import ServerFilterSet
from .kea import KeaClient
from .models import Server
from .utilities import (
    OptionalViewTab,
    check_dhcp_enabled,
    export_table,
    format_duration,
    format_leases,
)


@register_model_view(Server)
class ServerView(generic.ObjectView):
    queryset = Server.objects.all()


@register_model_view(Server, "edit")
class ServerEditView(generic.ObjectEditView):
    queryset = Server.objects.all()
    form = forms.ServerForm


@register_model_view(Server, "delete")
class ServerDeleteView(generic.ObjectDeleteView):
    queryset = Server.objects.all()


class ServerListView(generic.ObjectListView):
    queryset = Server.objects.all()
    table = tables.ServerTable
    filterset = ServerFilterSet
    filterset_form = forms.ServerFilterForm


class ServerBulkDeleteView(generic.BulkDeleteView):
    queryset = Server.objects.all()
    table = tables.ServerTable


@register_model_view(Server, "status")
class ServerStatusView(generic.ObjectView):
    queryset = Server.objects.all()
    tab = ViewTab(label="Status", weight=1000)
    template_name = "netbox_kea/server_status.html"

    def _get_ca_status(self, client: KeaClient) -> Dict[str, Any]:
        """Get the control agent status"""
        status = client.command("status-get")
        args = status[0]["arguments"]
        assert args is not None

        version = client.command("version-get")
        version_args = version[0]["arguments"]
        assert version_args is not None

        return {
            "PID": args["pid"],
            "Uptime": format_duration(int(args["uptime"])),
            "Time since reload": format_duration(int(args["reload"])),
            "Version": version_args["extended"],
        }

    def _get_dhcp_status(
        self, server: Server, client: KeaClient
    ) -> Dict[str, Dict[str, Any]]:
        resp: Dict[str, Dict[str, Any]] = {}

        # Map of name to pretty name
        service_names = {"dhcp6": "DHCPv6", "dhcp4": "DHCPv4"}
        services = []
        if server.dhcp6:
            services.append("dhcp6")
        if server.dhcp4:
            services.append("dhcp4")
        service_keys = list(services)

        dhcp_status = client.command("status-get", service=service_keys)
        dhcp_version = client.command("version-get", service=service_keys)
        assert len(dhcp_status) == len(services)
        assert len(dhcp_version) == len(services)
        for svc, status, version in zip(services, dhcp_status, dhcp_version):
            args = status["arguments"]
            assert args is not None

            version_args = version["arguments"]
            assert version_args is not None

            resp[service_names[svc]] = {
                "PID": args["pid"],
                "Uptime": format_duration(args["uptime"]),
                "Time since reload": format_duration(int(args["reload"])),
                "Version": version_args["extended"],
            }

            if (ha := args.get("high-availability")) is not None:
                # https://kea.readthedocs.io/en/latest/arm/hooks.html#load-balancing-configuration
                # Note that while the top-level parameter high-availability is a list,
                # only a single entry is currently supported.

                ha_servers = ha[0].get("ha-servers")
                ha_local = ha_servers.get("local", {})
                ha_remote = ha_servers.get("remote", {})
                resp[service_names[svc]].update(
                    {
                        "HA mode": ha[0].get("ha-mode"),
                        "HA local role": ha_local.get("role"),
                        "HA local state": ha_local.get("state"),
                        "HA remote connection interrupted": str(
                            ha_remote.get("connection-interrupted")
                        ),
                        "HA remote age (seconds)": ha_remote.get("age"),
                        "HA remote role": ha_remote.get("role"),
                        "HA remote last state": ha_remote.get("last-state"),
                        "HA remote in touch": ha_remote.get("in-touch"),
                        "HA remote unacked clients": ha_remote.get("unacked-clients"),
                        "HA remote unacked clients left": ha_remote.get(
                            "unacked-clients-left"
                        ),
                        "HA remote connecting clients": ha_remote.get(
                            "connecting-clients"
                        ),
                    }
                )
        return resp

    def _get_statuses(
        self, server: Server, client: KeaClient
    ) -> Dict[str, Dict[str, Any]]:
        return {
            "Control Agent": self._get_ca_status(client),
            **self._get_dhcp_status(server, client),
        }

    def get_extra_context(
        self, request: HttpResponse, instance: Server
    ) -> Dict[str, Any]:
        return {"statuses": self._get_statuses(instance, instance.get_client())}


class BaseServerLeasesView(generic.ObjectView):
    template_name = "netbox_kea/server_dhcp_leases.html"
    queryset = Server.objects.all()

    def get_leases_page(
        self, client: KeaClient, subnet: IPNetwork, page: Optional[str], per_page: int
    ) -> Tuple[List[Dict[str, Any]], Optional[str]]:
        if page:
            frm = page
        elif int(subnet.network) == 0:
            frm = str(subnet.network)
        else:
            frm = str(subnet.network - 1)

        resp = client.command(
            f"lease{self.dhcp_version}-get-page",
            service=[f"dhcp{self.dhcp_version}"],
            arguments={"from": frm, "limit": per_page},
            check=(0, 3),
        )

        if resp[0]["result"] == 3:
            return [], None

        args = resp[0]["arguments"]
        assert args is not None
        subnet_leases = args["leases"]
        next = (
            f"{subnet_leases[-1]['ip-address']}" if args["count"] == per_page else None
        )
        for i, lease in enumerate(args["leases"]):
            lease_ip = IPAddress(lease["ip-address"])
            if lease_ip not in subnet:
                subnet_leases = subnet_leases[:i]
                next = None
                break

        return format_leases(subnet_leases), next

    def get_leases(self, client: KeaClient, q: Any, by: str) -> List[Dict[str, Any]]:
        arguments: Dict[str, Any]
        command = ""
        multiple = True

        if by == constants.BY_IP:
            arguments = {"ip-address": q}
            multiple = False
        elif by == constants.BY_HW_ADDRESS:
            arguments = {"hw-address": q}
            command = "-by-hw-address"
        elif by == constants.BY_HOSTNAME:
            arguments = {"hostname": q}
            command = "-by-hostname"
        elif by == constants.BY_CLIENT_ID:
            arguments = {"client-id": q}
            command = "-by-client-id"
        elif by == constants.BY_SUBNET_ID:
            command = "-all"
            arguments = {"subnets": [int(q)]}
        elif by == constants.BY_DUID:
            command = "-by-duid"
            arguments = {"duid": q}
        else:
            # We should never get here because the
            # form should of been validated.
            raise AbortRequest(f"Invalid search by (this shouldn't happen): {by}")
        resp = client.command(
            f"lease{self.dhcp_version}-get{command}",
            service=[f"dhcp{self.dhcp_version}"],
            arguments=arguments,
            check=(0, 3),
        )

        if resp[0]["result"] == 3:
            return []

        args = resp[0]["arguments"]
        assert args is not None
        if multiple is True:
            return format_leases(args["leases"])
        return format_leases([args])

    def get_extra_context(
        self, request: HttpRequest, _instance: Server
    ) -> Dict[str, Any]:
        # For non-htmx requests.

        table = self.table([], user=request.user)
        form = self.form(request.GET) if "q" in request.GET else self.form()
        return {"form": form, "table": table}

    def get_export(self, request: HttpRequest, **kwargs) -> HttpResponse:
        form = self.form(request.GET)
        if not form.is_valid():
            messages.warning(request, "Invalid form for export.")
            return redirect(request.path)

        instance = self.get_object(**kwargs)

        by = form.cleaned_data["by"]
        q = form.cleaned_data["q"]
        client = instance.get_client()
        if by == constants.BY_SUBNET:
            leases = []
            page = ""  # start from the beginning
            while page is not None:
                page_leases, page = self.get_leases_page(
                    client,
                    q,
                    page,
                    per_page=get_paginate_count(request),
                )
                leases += page_leases
        else:
            leases = self.get_leases(client, q, by)

        table = self.table(leases, user=request.user)
        return export_table(
            table, "leases.csv", use_selected_columns=request.GET["export"] == "table"
        )

    def get(self, request: HttpRequest, **kwargs) -> HttpResponse:
        logger = logging.getLogger("netbox_kea.views.BaseServerDHCPLeasesVie")

        instance: Server = self.get_object(**kwargs)

        if resp := check_dhcp_enabled(instance, self.dhcp_version):
            return resp

        if "export" in request.GET:
            return self.get_export(request, **kwargs)

        if not is_htmx(request):
            return super().get(request, **kwargs)

        try:
            form = self.form(request.GET)
            if not form.is_valid():
                return render(
                    request,
                    "netbox_kea/server_dhcp_leases_htmx.html",
                    {
                        "is_embedded": False,
                        "form": form,
                        "table": self.table([]),
                        "paginate": False,
                    },
                )

            by = form.cleaned_data["by"]
            q = form.cleaned_data["q"]
            client = instance.get_client()
            if by == "subnet":
                leases, next_page = self.get_leases_page(
                    client,
                    q,
                    form.cleaned_data["page"],
                    per_page=get_paginate_count(request),
                )
                paginate = True
            else:
                paginate = False
                next_page = None
                leases = self.get_leases(client, q, by)

            return render(
                request,
                "netbox_kea/server_dhcp_leases_htmx.html",
                {
                    "is_embedded": False,
                    "delete_action": reverse(
                        f"plugins:netbox_kea:server_leases{self.dhcp_version}_delete",
                        args=[instance.pk],
                    ),
                    "form": form,
                    "table": self.table(leases, user=request.user),
                    "next_page": next_page,
                    "paginate": paginate,
                    "page_lengths": EnhancedPaginator.default_page_lengths,
                },
            )
        except Exception as e:
            logger.exception("Got exception on DHCP leases HTMX handler")
            return render(
                request,
                "netbox_kea/exception_htmx.html",
                {"type_": type(e).__name__, "exception": str(e)},
            )


@register_model_view(Server, "leases6")
class ServerLeases6View(BaseServerLeasesView):
    tab = OptionalViewTab(
        label="DHCPv6 Leases", weight=1010, is_enabled=lambda s: s.dhcp6
    )
    form = forms.Leases6SearchForm
    table = tables.LeaseTable6
    dhcp_version = 6


@register_model_view(Server, "leases4")
class ServerLeases4View(BaseServerLeasesView):
    tab = OptionalViewTab(
        label="DHCPv4 Leases", weight=1020, is_enabled=lambda s: s.dhcp4
    )
    form = forms.Leases4SearchForm
    table = tables.LeaseTable4
    dhcp_version = 4


class BaseServerLeasesDeleteView(
    GetReturnURLMixin, generic.ObjectView, metaclass=ABCMeta
):
    queryset = Server.objects.all()
    default_return_url = "plugins:netbox_kea:server_list"

    def delete_lease(self, client: KeaClient, ip: str) -> None:
        client.command(
            f"lease{self.dhcp_version}-del",
            arguments={"ip-address": ip},
            service=[f"dhcp{self.dhcp_version}"],
            check=(0, 3),
        )

    def get(self, request: HttpRequest, **kwargs):
        return redirect(self.get_return_url(request, obj=self.get_object(**kwargs)))

    def post(self, request: HttpRequest, **kwargs) -> HttpResponse:
        instance: Server = self.get_object(**kwargs)
        form = self.form(request.POST)

        if not form.is_valid():
            messages.warning(request, str(form.errors))
            return redirect(self.get_return_url(request, obj=instance))

        lease_ips = form.cleaned_data["pk"]
        if "_confirm" not in request.POST:
            if len(lease_ips) == 0:
                messages.warning(request, "No leases were selected for deletion.")
                return redirect(self.get_return_url(request, obj=instance))
            return render(
                request,
                "netbox_kea/server_leases_delete.html",
                {
                    "lease_ips": form.cleaned_data["pk"],
                    "form": form,
                    "return_url": self.get_return_url(request, obj=instance),
                },
            )

        client = instance.get_client()

        for ip in lease_ips:
            try:
                self.delete_lease(client, ip)
            except Exception as e:
                messages.error(request, f"Error deleting lease {ip}: {repr(e)}")
                return redirect(self.get_return_url(request, obj=instance))

        messages.success(
            request, f"Deleted {len(lease_ips)} DHCPv{self.dhcp_version} lease(s)."
        )
        return redirect(self.get_return_url(request, obj=instance))


class ServerLeases6DeleteView(BaseServerLeasesDeleteView):
    form = forms.Lease6DeleteForm
    dhcp_version = 6


class ServerLeases4DeleteView(BaseServerLeasesDeleteView):
    form = forms.Lease4DeleteForm
    dhcp_version = 4


class BaseServerDHCPSubnetsView(generic.ObjectView, metaclass=ABCMeta):
    queryset = Server.objects.all()
    template_name = "netbox_kea/server_dhcp_subnets.html"

    def get_subnet_table(
        self, request: HttpRequest, instance: Server
    ) -> tables.SubnetTable:
        client = instance.get_client()
        subnets = self.get_subnets(client)
        table = tables.SubnetTable(
            f"plugins:netbox_kea:server_leases{self.dhcp_version}",
            instance.pk,
            subnets,
            user=request.user,
        )
        table.configure(request)
        return table

    def get_extra_context(
        self, request: HttpRequest, instance: Server
    ) -> Dict[str, Any]:
        return {"table": self.get_subnet_table(request, instance)}

    def get(self, request: HttpRequest, **kwargs) -> HttpResponse:
        instance = self.get_object(**kwargs)

        if resp := check_dhcp_enabled(instance, self.dhcp_version):
            return resp

        if "export" not in request.GET:
            return super().get(request, **kwargs)

        table = self.get_subnet_table(request, instance)

        return export_table(
            table,
            filename=f"kea-dhcpv{self.dhcp_version}-subnets.csv",
            use_selected_columns=request.GET["export"] == "table",
        )


@register_model_view(Server, "subnets6")
class ServerDHCP6SubnetsView(BaseServerDHCPSubnetsView):
    tab = OptionalViewTab(
        label="DHCPv6 Subnets", weight=1030, is_enabled=lambda s: s.dhcp6
    )
    dhcp_version = 6

    def get_subnets(self, client: KeaClient) -> List[Dict[str, Any]]:
        config = client.command("config-get", service=["dhcp6"])
        assert config[0]["arguments"] is not None
        subnets = config[0]["arguments"]["Dhcp6"]["subnet6"]
        return [
            {"id": s["id"], "subnet": s["subnet"]}
            for s in subnets
            if "id" in s and "subnet" in s
        ]


@register_model_view(Server, "subnets4")
class ServerDHCP4SubnetsView(BaseServerDHCPSubnetsView):
    tab = OptionalViewTab(
        label="DHCPv4 Subnets", weight=1040, is_enabled=lambda s: s.dhcp4
    )
    dhcp_version = 4

    def get_subnets(self, client: KeaClient) -> List[Dict[str, Any]]:
        config = client.command("config-get", service=["dhcp4"])
        assert config[0]["arguments"] is not None
        subnets = config[0]["arguments"]["Dhcp4"]["subnet4"]
        return [
            {"id": s["id"], "subnet": s["subnet"]}
            for s in subnets
            if "id" in s and "subnet" in s
        ]
