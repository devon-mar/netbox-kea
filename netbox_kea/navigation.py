from extras.plugins import PluginMenuButton, PluginMenuItem
from utilities.choices import ButtonColorChoices

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
                color=ButtonColorChoices.GREEN,
                permissions=["netbox_kea.add_server"],
            ),
        ),
    ),
)
