from extras.plugins import PluginMenuButton, PluginMenuItem
from utilities.choices import ButtonColorChoices

menu_items = (
    PluginMenuItem(
        link="plugins:netbox_kea:server_list",
        link_text="Servers",
        # So that this doesn't show up in the navigation bar
        # when logged out.
        permissions=["netbox_kea.server_view"],
        buttons=(
            PluginMenuButton(
                link="plugins:netbox_kea:server_add",
                title="Add",
                icon_class="mdi mdi-plus-thick",
                color=ButtonColorChoices.GREEN,
            ),
        ),
    ),
)
