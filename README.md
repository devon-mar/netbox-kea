# NetBox plugin for the Kea DHCP server

This plugin allows you to view Kea status, leases and subnets in NetBox. Go directly from a NetBox device/VM to a DHCP lease and back!

## Features

- Uses the Kea management API
- View Kea daemon statuses. 
- Supports Kea's DHCPv4 and DHCPv6 servers.
- View, delete, export and search for DHCP leases.
- Search for NetBox devices/VMs directly from DHCP leases.
- View DHCP subnets from Kea's configuration.
- REST API and GraphQL support for managing Server objects.

## Limitations

- Due to limitations in the Kea management API, pagination is only supported when searching for leases by subnet.
  Additionally, you can only go forwards, not backwards.

- Searching for leases by subnet ID does not support pagination. This may be an expensive operation depending on the subnet size.

- Kea doesn't provide a way to get a list of subnets without an additional hook library.
  Thus, this plugin lists subnets using the `config-get` command. This means that the entire config will be fetched just to get the configured subnets!
  This may be an expensive operation.

## Requirements

- [Kea Control Agent](https://kea.readthedocs.io/en/latest/arm/agent.html)
- The [`lease_cmds`](https://kea.readthedocs.io/en/latest/arm/hooks.html#lease-cmds-lease-commands-for-easier-lease-management) hook library

## Compatibility
- This plugin was tested with Kea v2.2.0 with the `memfile` lease database.
  Other versions and lease databases may also work.

## Installation

1. Add `netbox-kea` to `local_requirements.txt`.

2. Enable the plugin in `configuration.py`
    ```python
    PLUGINS = ["netbox_kea"]
    ```
3. Run `./migrate.py migrate`
