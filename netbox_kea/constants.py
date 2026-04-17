BY_IP = "ip"
BY_HOSTNAME = "hostname"
BY_DUID = "duid"
BY_SUBNET = "subnet"
BY_SUBNET_ID = "subnet_id"
BY_HW_ADDRESS = "hw"
BY_CLIENT_ID = "client_id"

HEX_STRING_REGEX = r"^([0-9A-Fa-f]{2}[:-]?)*([0-9A-Fa-f]{2})$"

# kea/src/lib/dhcp
# RFC8415 section 11.1
DUID_MAX_OCTETS = 128
DUID_MIN_OCTETS = 1
CLIENT_ID_MAX_OCTETS = DUID_MAX_OCTETS
CLIENT_ID_MIN_OCTETS = 2

KEA_BASIC_PASSWORD = "kea1234"
KEA_BASIC_URL = "http://nginx"
KEA_BASIC_USERNAME = "kea"
KEA_CA = "/certs/ca.crt"
KEA_CERT_URL = "https://nginx:444"
KEA_CLIENT_CERT = "/certs/netbox.crt"
KEA_CLIENT_KEY = "/certs/netbox.key"
KEA_HTTPS_URL = "https://nginx"
KEA6_URL = "http://kea-dhcp6:8000"
KEA4_URL = "http://kea-dhcp4:8000"

NETBOX_URL = "http://localhost:8000"
PLUGIN_BASE_URL = f"{NETBOX_URL}/plugins/kea"
KEA6_URL_SECURE = "https://kea-dhcp6:8001"
KEA4_URL_SECURE = "https://kea-dhcp4:8001"
KEA6_URL_CERT = "https://kea-dhcp6:8002"
KEA4_URL_CERT = "https://kea-dhcp4:8002"
KEA6_URL_BASIC = "https://kea-dhcp6:8003"
KEA4_URL_BASIC = "https://kea-dhcp4:8003"
