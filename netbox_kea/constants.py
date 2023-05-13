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
