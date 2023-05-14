from extras.plugins import PluginConfig


class NetBoxKeaConfig(PluginConfig):
    name = "netbox_kea"
    verbose_name = "Kea"
    description = "Kea integration for NetBox"
    version = "0.1.0"
    base_url = "kea"
    default_settings = {"kea_timeout": 30}


config = NetBoxKeaConfig
