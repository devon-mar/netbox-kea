from netbox.plugins import PluginMenuButton, PluginMenuItem

menu_items = (
    PluginMenuItem(
        link="plugins:netbox_kea:server_list",
        link_text="Servers",
        permissions=["netbox_kea.view_server"],
        buttons=(
            PluginMenuButton(
                link="plugins:netbox_kea:server_add",
                title="Add",
                icon_class="mdi mdi-plus-thick",
                permissions=["netbox_kea.add_server"],
            ),
        ),
    ),
)
