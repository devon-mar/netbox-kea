from typing import Any, Dict, Literal, Optional

from django import forms
from django.core.exceptions import ValidationError
from netaddr import EUI, AddrFormatError, IPAddress, IPNetwork, mac_unix_expanded
from netbox.forms import NetBoxModelForm
from utilities.forms import BootstrapMixin

from . import constants
from .models import Server
from .utilities import is_hex_string


class ServerForm(NetBoxModelForm):
    class Meta:
        model = Server
        fields = (
            "name",
            "server_url",
            "username",
            "password",
            "ssl_verify",
            "client_cert_path",
            "client_key_path",
            "ca_file_path",
            "tags",
        )


class VeryHiddenInput(forms.HiddenInput):
    """Returns an empty string on render."""

    input_type = "hidden"
    template_name = ""

    def render(self, name: str, value: Any, attrs: Any, renderer: Any) -> str:
        return ""


class BaseLeasesSarchForm(BootstrapMixin, forms.Form):
    q = forms.CharField(label="Search")
    page = forms.CharField(required=False, widget=VeryHiddenInput)

    def clean(self) -> Optional[Dict[str, Any]]:
        ip_version = self.Meta.ip_version
        cleaned_data = super().clean()
        q = cleaned_data.get("q")
        by = cleaned_data.get("by")

        if q and not by:
            raise ValidationError({"by": "Search attribute is empty."})
        elif by and not q:
            raise ValidationError({"q": "Search value is empty."})

        if by == constants.BY_SUBNET:
            try:
                if "/" not in q:
                    raise ValidationError({"q": "CIDR mask is required"})
                net = IPNetwork(q, version=ip_version)
                if net.ip != net.cidr.ip:
                    raise ValidationError(
                        {"q": f"{net} is not a valid prefix. Did you mean {net.cidr}?"}
                    )
                cleaned_data["q"] = net
            except (AddrFormatError, TypeError, ValueError) as e:
                raise ValidationError(
                    {"q": f"Invalid IPv{ip_version} subnet: {cleaned_data['q']}"}
                ) from e
        elif by == constants.BY_SUBNET_ID:
            try:
                i = int(q)
                if i <= 0:
                    raise ValidationError({"q": f"Invalid subnet ID: {q}"})
                cleaned_data["q"] = i
            except ValueError as e:
                raise ValidationError(
                    {"q": f"Subnet ID must be an integer: {q}"}
                ) from e
        elif by == constants.BY_IP:
            try:
                # use IPAddress to normalize values
                cleaned_data["q"] = str(IPAddress(q, version=ip_version))
            except (AddrFormatError, TypeError, ValueError) as e:
                raise ValidationError(
                    {"q": f"Invalid IPv{ip_version} address: {q}"}
                ) from e
        elif by in (constants.BY_HW_ADDRESS):
            try:
                cleaned_data["q"] = str(EUI(q, version=48, dialect=mac_unix_expanded))
            except (AddrFormatError, TypeError, ValueError) as e:
                raise ValidationError({"q": f"Invalid hardware address: {q}"}) from e
        elif by in constants.BY_DUID:
            if not is_hex_string(
                q, constants.DUID_MIN_OCTETS, constants.DUID_MAX_OCTETS
            ):
                raise ValidationError({"q": f"Invalid DUID: {q}"})
            cleaned_data["q"] = q.replace("-", "")
        elif by in constants.BY_CLIENT_ID:
            if not is_hex_string(
                q, constants.CLIENT_ID_MIN_OCTETS, constants.DUID_MAX_OCTETS
            ):
                raise ValidationError({"q": f"Invalid client ID: {q}"})
            cleaned_data["q"] = q.replace("-", "")

        page = cleaned_data["page"]
        if page:
            if by != constants.BY_SUBNET:
                raise ValidationError({"page": "page is only supported with subnet."})
            try:
                page_ip = IPAddress(page, version=ip_version)
                if page_ip not in cleaned_data["q"]:
                    raise ValidationError({"page": "page is not in the given subnet"})

                cleaned_data["page"] = str(page_ip)
            except AddrFormatError as e:
                raise ValidationError({"page": f"Invalid IP: {page}"}) from e


class Leases4SearchForm(BaseLeasesSarchForm):
    by = forms.ChoiceField(
        label="Attribute",
        choices=(
            (constants.BY_IP, "IP Address"),
            (constants.BY_HOSTNAME, "Hostname"),
            (constants.BY_HW_ADDRESS, "Hardware Address"),
            (constants.BY_CLIENT_ID, "Client ID"),
            (constants.BY_SUBNET, "Subnet"),
            (constants.BY_SUBNET_ID, "Subnet ID"),
        ),
        required=True,
    )

    class Meta:
        ip_version = 4


class Leases6SearchForm(BaseLeasesSarchForm):
    by = forms.ChoiceField(
        label="Attribute",
        choices=(
            (constants.BY_IP, "IP Address"),
            (constants.BY_HOSTNAME, "Hostname"),
            (constants.BY_DUID, "DUID"),
            (constants.BY_SUBNET, "Subnet"),
            (constants.BY_SUBNET_ID, "Subnet ID"),
        ),
        required=True,
    )

    class Meta:
        ip_version = 6


class MultipleIPField(forms.MultipleChoiceField):
    def __init__(self, version: Literal[6, 4], *args, **kwargs) -> None:
        self._version = version
        super().__init__(*args, widget=forms.MultipleHiddenInput, **kwargs)

    def clean(self, value: Any) -> Any:
        if not isinstance(value, list):
            raise forms.ValidationError(f"Expected a list, got {type(value)}.")

        try:
            return [str(IPAddress(ip, version=self._version)) for ip in value]
        except (AddrFormatError, ValueError) as e:
            raise forms.ValidationError("Invalid IP address.") from e


class Lease6DeleteForm(forms.Form):
    pk = MultipleIPField(6)


class Lease4DeleteForm(forms.Form):
    pk = MultipleIPField(4)
