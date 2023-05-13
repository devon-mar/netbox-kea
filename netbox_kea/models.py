import os

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
        )

    def clean(self) -> None:
        super().clean()

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
        try:
            client.command("version-get")
        except Exception as e:
            raise ValidationError(
                {"server_url": f"Unable to get server version {repr(e)}"}
            ) from e
