import os

from django.conf import settings
from django.core.exceptions import ValidationError
from django.db import models
from django.urls import reverse
from netbox.models import NetBoxModel

from .kea import KeaClient


class Server(NetBoxModel):
    name = models.CharField(unique=True, max_length=255)
    server_url = models.CharField(verbose_name="Server URL", max_length=255)
    username = models.CharField(null=True, blank=True, max_length=255)
    password = models.CharField(null=True, blank=True, max_length=255)
    ssl_verify = models.BooleanField(
        default=True,
        verbose_name="SSL Verification",
        help_text="Enable SSL certificate verification. Disable with caution!",
    )
    client_cert_path = models.CharField(
        max_length=4096,
        null=True,
        blank=True,
        verbose_name="Client Certificate",
        help_text="Optional client certificate.",
    )
    client_key_path = models.CharField(
        max_length=4096,
        null=True,
        blank=True,
        verbose_name="Private Key",
        help_text="Optional client key.",
    )
    ca_file_path = models.CharField(
        max_length=4096,
        null=True,
        blank=True,
        verbose_name="CA File Path",
        help_text="The specific CA certificate file to use for SSL verification.",
    )
    dhcp6 = models.BooleanField(verbose_name="DHCPv6", default=True)
    dhcp4 = models.BooleanField(verbose_name="DHCPv4", default=True)

    class Meta:
        ordering = ("name",)

    def __str__(self):
        return self.name

    def get_absolute_url(self):
        return reverse("plugins:netbox_kea:server", args=[self.pk])

    def get_client(self) -> KeaClient:
        return KeaClient(
            url=self.server_url,
            username=self.username,
            password=self.password,
            verify=self.ca_file_path or self.ssl_verify,
            client_cert=self.client_cert_path or None,
            client_key=self.client_key_path or None,
            timeout=settings.PLUGINS_CONFIG["netbox_kea"]["kea_timeout"],
        )

    def clean(self) -> None:
        super().clean()

        if self.dhcp4 is False and self.dhcp6 is False:
            raise ValidationError(
                {"dhcp6": "At one of DHCPv4 and DHCPv6 needs to be enabled."}
            )

        if (self.client_cert_path and not self.client_key_path) or (
            not self.client_cert_path and self.client_key_path
        ):
            raise ValidationError(
                {
                    "client_cert_path": "Client certificate and client private key must be used together."
                }
            )

        if self.client_cert_path and not os.path.isfile(self.client_cert_path):
            raise ValidationError(
                {"client_cert_path": "Client certificate doesn't exist."}
            )
        if self.client_key_path and not os.path.isfile(self.client_key_path):
            raise ValidationError(
                {"client_key_path": "Client private key doesn't exist."}
            )

        if self.ca_file_path and not self.ssl_verify:
            raise ValidationError(
                {
                    "ca_file_path": "Cannot specify a CA file when SSL verification is disabled."
                }
            )

        client = self.get_client()
        if self.dhcp6:
            try:
                client.command("version-get", service=["dhcp6"])
            except Exception as e:
                raise ValidationError(
                    {"dhcp6": f"Unable to get DHCPv6 version: {repr(e)}"}
                ) from e
        if self.dhcp4:
            try:
                client.command("version-get", service=["dhcp4"])
            except Exception as e:
                raise ValidationError(
                    {"dhcp4": f"Unable to get DHCPv4 version: {repr(e)}"}
                ) from e


class DHCPSubnet(NetBoxModel):
    class Meta:
        managed = False

    dhcp_version = models.PositiveIntegerField()
    server_pk = models.PositiveIntegerField()
    subnet = models.CharField()
    shared_network = models.CharField()
