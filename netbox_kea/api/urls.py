from netbox.api.routers import NetBoxRouter

from . import views

app_name = "netbox_kea"

router = NetBoxRouter()
router.register("servers", views.ServerViewSet)

urlpatterns = router.urls
