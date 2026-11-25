"""Domain enumeration types for the NetPulse Observability Platform.

All enumerations inherit from :class:`enum.StrEnum` so members serialize cleanly
to canonical lowercase strings in JSON, SQLAlchemy ``String`` columns, Pydantic
models, and URL query parameters while preserving strong static typing.
"""

from __future__ import annotations

from enum import StrEnum
from typing import TypeVar

E = TypeVar("E", bound=StrEnum)


class UserRole(StrEnum):
    """Role-based access control (RBAC) levels scoped to an organization."""

    SUPER_ADMIN = "super_admin"
    ORG_ADMIN = "org_admin"
    ADMIN = "admin"
    NETOPS = "netops"
    OPERATOR = "operator"
    ANALYST = "analyst"
    VIEWER = "viewer"
    SERVICE_ACCOUNT = "service_account"

    @property
    def rank(self) -> int:
        """Numeric privilege rank used for hierarchical authorization checks."""
        return _USER_ROLE_RANK[self]

    @property
    def is_admin(self) -> bool:
        """Return ``True`` if this role has administrative privileges."""
        return self in {UserRole.SUPER_ADMIN, UserRole.ORG_ADMIN, UserRole.ADMIN}

    @property
    def can_write(self) -> bool:
        """Return ``True`` if this role may mutate inventory, alerts, or configs."""
        return self.rank >= UserRole.OPERATOR.rank

    def has_at_least(self, required: UserRole | str) -> bool:
        """Return ``True`` if this role meets or exceeds *required* privilege."""
        target = UserRole(required) if not isinstance(required, UserRole) else required
        return self.rank >= target.rank


_USER_ROLE_RANK: dict[UserRole, int] = {
    UserRole.VIEWER: 10,
    UserRole.ANALYST: 20,
    UserRole.SERVICE_ACCOUNT: 30,
    UserRole.OPERATOR: 40,
    UserRole.NETOPS: 50,
    UserRole.ADMIN: 70,
    UserRole.ORG_ADMIN: 80,
    UserRole.SUPER_ADMIN: 100,
}


class AuditAction(StrEnum):
    """Auditable platform security, configuration, and lifecycle events."""

    CREATE = "create"
    READ = "read"
    UPDATE = "update"
    DELETE = "delete"
    RESTORE = "restore"
    LOGIN = "login"
    LOGOUT = "logout"
    LOGIN_FAILED = "login_failed"
    TOKEN_REFRESH = "token_refresh"
    SESSION_REVOKE = "session_revoke"
    PASSWORD_CHANGE = "password_change"
    MFA_ENABLE = "mfa_enable"
    MFA_DISABLE = "mfa_disable"
    API_KEY_CREATE = "api_key_create"
    API_KEY_REVOKE = "api_key_revoke"
    CREDENTIAL_ACCESS = "credential_access"
    CREDENTIAL_ROTATE = "credential_rotate"
    CONFIG_BACKUP = "config_backup"
    CONFIG_RESTORE = "config_restore"
    CONFIG_DIFF = "config_diff"
    ALERT_ACK = "alert_ack"
    ALERT_RESOLVE = "alert_resolve"
    ALERT_SILENCE = "alert_silence"
    INCIDENT_CREATE = "incident_create"
    INCIDENT_ASSIGN = "incident_assign"
    INCIDENT_RESOLVE = "incident_resolve"
    PLAYBOOK_RUN = "playbook_run"
    PLAYBOOK_APPROVE = "playbook_approve"
    DISCOVERY_START = "discovery_start"
    DISCOVERY_CANCEL = "discovery_cancel"
    COMPLIANCE_EVAL = "compliance_eval"
    REPORT_GENERATE = "report_generate"
    EXPORT = "export"
    PERMISSION_CHANGE = "permission_change"
    WEBHOOK_TRIGGER = "webhook_trigger"
    SETTINGS_UPDATE = "settings_update"


class DeviceType(StrEnum):
    """Primary functional classification of a managed network or compute asset."""

    ROUTER = "router"
    SWITCH = "switch"
    CORE_SWITCH = "core_switch"
    DISTRIBUTION_SWITCH = "distribution_switch"
    ACCESS_SWITCH = "access_switch"
    FIREWALL = "firewall"
    LOAD_BALANCER = "load_balancer"
    WIRELESS_CONTROLLER = "wireless_controller"
    ACCESS_POINT = "access_point"
    SDWAN_EDGE = "sdwan_edge"
    CLOUD_GATEWAY = "cloud_gateway"
    GATEWAY = "gateway"
    MODEM = "modem"
    OPTICAL_TRANSPONDER = "optical_transponder"
    SERVER = "server"
    VIRTUAL_MACHINE = "virtual_machine"
    HYPERVISOR = "hypervisor"
    CONTAINER_HOST = "container_host"
    STORAGE = "storage"
    UPS = "ups"
    PDU = "pdu"
    BASTION = "bastion"
    IOT = "iot"
    CAMERA = "camera"
    PRINTER = "printer"
    UNKNOWN = "unknown"

    @property
    def is_network_infrastructure(self) -> bool:
        """Return ``True`` for L2/L3 forwarding, routing, and security appliances."""
        return self in {
            DeviceType.ROUTER,
            DeviceType.SWITCH,
            DeviceType.CORE_SWITCH,
            DeviceType.DISTRIBUTION_SWITCH,
            DeviceType.ACCESS_SWITCH,
            DeviceType.FIREWALL,
            DeviceType.LOAD_BALANCER,
            DeviceType.WIRELESS_CONTROLLER,
            DeviceType.ACCESS_POINT,
            DeviceType.SDWAN_EDGE,
            DeviceType.CLOUD_GATEWAY,
            DeviceType.GATEWAY,
            DeviceType.OPTICAL_TRANSPONDER,
        }


class DeviceStatus(StrEnum):
    """Operational availability state of a managed device."""

    UP = "up"
    DOWN = "down"
    DEGRADED = "degraded"
    WARNING = "warning"
    CRITICAL = "critical"
    MAINTENANCE = "maintenance"
    UNREACHABLE = "unreachable"
    PROVISIONING = "provisioning"
    DECOMMISSIONED = "decommissioned"
    UNKNOWN = "unknown"

    @property
    def is_healthy(self) -> bool:
        """Return ``True`` when the device is operating normally."""
        return self is DeviceStatus.UP

    @property
    def is_problem(self) -> bool:
        """Return ``True`` when the device indicates an operational fault."""
        return self in {
            DeviceStatus.DOWN,
            DeviceStatus.DEGRADED,
            DeviceStatus.WARNING,
            DeviceStatus.CRITICAL,
            DeviceStatus.UNREACHABLE,
        }


class DeviceVendor(StrEnum):
    """Hardware manufacturer or operating system vendor for a device."""

    CISCO = "cisco"
    ARISTA = "arista"
    JUNIPER = "juniper"
    PALO_ALTO = "palo_alto"
    FORTINET = "fortinet"
    CHECKPOINT = "checkpoint"
    F5 = "f5"
    HPE_ARUBA = "hpe_aruba"
    DELL = "dell"
    HUAWEI = "huawei"
    MIKROTIK = "mikrotik"
    UBIQUITI = "ubiquiti"
    MERAKI = "meraki"
    EXTREME = "extreme"
    NOKIA = "nokia"
    CUMULUS = "cumulus"
    RUCKUS = "ruckus"
    SONICWALL = "sonicwall"
    SOPHOS = "sophos"
    CITRIX = "citrix"
    LINUX = "linux"
    WINDOWS = "windows"
    VMWARE = "vmware"
    AWS = "aws"
    AZURE = "azure"
    GCP = "gcp"
    APC = "apc"
    EATON = "eaton"
    GENERIC = "generic"
    UNKNOWN = "unknown"


class InterfaceStatus(StrEnum):
    """Administrative or operational status of a network interface (RFC 2863)."""

    UP = "up"
    DOWN = "down"
    TESTING = "testing"
    UNKNOWN = "unknown"
    DORMANT = "dormant"
    NOT_PRESENT = "not_present"
    LOWER_LAYER_DOWN = "lower_layer_down"
    ADMIN_DOWN = "admin_down"

    @classmethod
    def from_snmp_code(cls, code: int) -> InterfaceStatus:
        """Translate RFC 2863 IF-MIB integer status codes (1..7) into an enum."""
        mapping: dict[int, InterfaceStatus] = {
            1: cls.UP,
            2: cls.DOWN,
            3: cls.TESTING,
            4: cls.UNKNOWN,
            5: cls.DORMANT,
            6: cls.NOT_PRESENT,
            7: cls.LOWER_LAYER_DOWN,
        }
        return mapping.get(code, cls.UNKNOWN)


class InterfaceType(StrEnum):
    """Physical or logical interface technology classification."""

    ETHERNET = "ethernet"
    FAST_ETHERNET = "fast_ethernet"
    GIGABIT_ETHERNET = "gigabit_ethernet"
    TEN_GIGABIT_ETHERNET = "ten_gigabit_ethernet"
    TWENTY_FIVE_GIGABIT_ETHERNET = "twenty_five_gigabit_ethernet"
    FORTY_GIGABIT_ETHERNET = "forty_gigabit_ethernet"
    HUNDRED_GIGABIT_ETHERNET = "hundred_gigabit_ethernet"
    FIBER = "fiber"
    SFP = "sfp"
    QSFP = "qsfp"
    LOOPBACK = "loopback"
    VLAN = "vlan"
    SVI = "svi"
    LAG = "lag"
    PORT_CHANNEL = "port_channel"
    BRIDGE = "bridge"
    TUNNEL = "tunnel"
    GRE = "gre"
    IPSEC = "ipsec"
    VXLAN = "vxlan"
    WIRELESS = "wireless"
    CELLULAR = "cellular"
    SERIAL = "serial"
    MANAGEMENT = "management"
    VIRTUAL = "virtual"
    OTHER = "other"


class DuplexMode(StrEnum):
    """Ethernet link duplex negotiation mode."""

    FULL = "full"
    HALF = "half"
    AUTO = "auto"
    UNKNOWN = "unknown"


class ProtocolType(StrEnum):
    """Network transport, telemetry, or management protocol."""

    ICMP = "icmp"
    SNMP = "snmp"
    SSH = "ssh"
    TELNET = "telnet"
    NETCONF = "netconf"
    RESTCONF = "restconf"
    GNMI = "gnmi"
    HTTP = "http"
    HTTPS = "https"
    TCP = "tcp"
    UDP = "udp"
    DNS = "dns"
    BGP = "bgp"
    OSPF = "ospf"
    SYSLOG = "syslog"
    NETFLOW = "netflow"
    SFLOW = "sflow"
    IPFIX = "ipfix"
    WMI = "wmi"
    WINRM = "winrm"
    PROMETHEUS = "prometheus"
    OTLP = "otlp"


class CredentialType(StrEnum):
    """Authentication mechanism stored in an encrypted credential profile."""

    SNMP_V1 = "snmp_v1"
    SNMP_V2C = "snmp_v2c"
    SNMP_V3 = "snmp_v3"
    SSH_PASSWORD = "ssh_password"
    SSH_KEY = "ssh_key"
    API_TOKEN = "api_token"
    BASIC_AUTH = "basic_auth"
    OAUTH2 = "oauth2"
    NETCONF = "netconf"
    WMI = "wmi"
    WINRM = "winrm"
    AWS_IAM = "aws_iam"
    AZURE_SP = "azure_sp"
    GCP_SA = "gcp_sa"
    CERTIFICATE = "certificate"

    @property
    def default_port(self) -> int:
        """Return the conventional TCP/UDP port for this credential type."""
        ports: dict[CredentialType, int] = {
            CredentialType.SNMP_V1: 161,
            CredentialType.SNMP_V2C: 161,
            CredentialType.SNMP_V3: 161,
            CredentialType.SSH_PASSWORD: 22,
            CredentialType.SSH_KEY: 22,
            CredentialType.NETCONF: 830,
            CredentialType.API_TOKEN: 443,
            CredentialType.BASIC_AUTH: 443,
            CredentialType.OAUTH2: 443,
            CredentialType.CERTIFICATE: 443,
            CredentialType.WMI: 135,
            CredentialType.WINRM: 5986,
            CredentialType.AWS_IAM: 443,
            CredentialType.AZURE_SP: 443,
            CredentialType.GCP_SA: 443,
        }
        return ports.get(self, 443)


class SnmpVersion(StrEnum):
    """SNMP protocol versions supported by the polling engine."""

    V1 = "v1"
    V2C = "v2c"
    V3 = "v3"


class SnmpAuthProtocol(StrEnum):
    """SNMPv3 USM authentication digest algorithms."""

    NONE = "none"
    MD5 = "md5"
    SHA = "sha"
    SHA224 = "sha224"
    SHA256 = "sha256"
    SHA384 = "sha384"
    SHA512 = "sha512"


class SnmpPrivProtocol(StrEnum):
    """SNMPv3 USM privacy/encryption ciphers."""

    NONE = "none"
    DES = "des"
    TRIPLE_DES = "3des"
    AES128 = "aes128"
    AES192 = "aes192"
    AES256 = "aes256"


class AlertSeverity(StrEnum):
    """Severity classification for alerts and rule evaluations."""

    INFO = "info"
    LOW = "low"
    WARNING = "warning"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"
    EMERGENCY = "emergency"

    @property
    def rank(self) -> int:
        """Numeric ordering where higher numbers indicate greater severity."""
        return _ALERT_SEVERITY_RANK[self]

    def is_at_least(self, other: AlertSeverity | str) -> bool:
        """Return ``True`` if this severity is greater than or equal to *other*."""
        target = AlertSeverity(other) if not isinstance(other, AlertSeverity) else other
        return self.rank >= target.rank


_ALERT_SEVERITY_RANK: dict[AlertSeverity, int] = {
    AlertSeverity.INFO: 10,
    AlertSeverity.LOW: 20,
    AlertSeverity.WARNING: 30,
    AlertSeverity.MEDIUM: 40,
    AlertSeverity.HIGH: 60,
    AlertSeverity.CRITICAL: 80,
    AlertSeverity.EMERGENCY: 100,
}


class AlertStatus(StrEnum):
    """Lifecycle status of an alert instance."""

    FIRING = "firing"
    ACTIVE = "active"
    ACKNOWLEDGED = "acknowledged"
    SILENCED = "silenced"
    SUPPRESSED = "suppressed"
    RESOLVED = "resolved"
    EXPIRED = "expired"

    @property
    def is_open(self) -> bool:
        """Return ``True`` when the alert has not yet been resolved or expired."""
        return self in {
            AlertStatus.FIRING,
            AlertStatus.ACTIVE,
            AlertStatus.ACKNOWLEDGED,
            AlertStatus.SILENCED,
            AlertStatus.SUPPRESSED,
        }


class IncidentStatus(StrEnum):
    """Workflow state for an operational incident."""

    OPEN = "open"
    INVESTIGATING = "investigating"
    IDENTIFIED = "identified"
    MITIGATED = "mitigated"
    MONITORING = "monitoring"
    RESOLVED = "resolved"
    CLOSED = "closed"
    POSTMORTEM = "postmortem"

    @property
    def is_terminal(self) -> bool:
        """Return ``True`` when the incident is closed or resolved."""
        return self in {IncidentStatus.RESOLVED, IncidentStatus.CLOSED}


class IncidentPriority(StrEnum):
    """Incident response priority tier with associated default SLA targets."""

    P1 = "p1"
    P2 = "p2"
    P3 = "p3"
    P4 = "p4"
    P5 = "p5"

    @property
    def sla_response_minutes(self) -> int:
        """Target acknowledgement time in minutes."""
        return {
            IncidentPriority.P1: 15,
            IncidentPriority.P2: 30,
            IncidentPriority.P3: 120,
            IncidentPriority.P4: 480,
            IncidentPriority.P5: 1440,
        }[self]

    @property
    def sla_resolution_minutes(self) -> int:
        """Target resolution time in minutes."""
        return {
            IncidentPriority.P1: 240,
            IncidentPriority.P2: 480,
            IncidentPriority.P3: 1440,
            IncidentPriority.P4: 4320,
            IncidentPriority.P5: 10080,
        }[self]


class RuleOperator(StrEnum):
    """Comparison and pattern operators supported by alerting rules."""

    GT = "gt"
    GTE = "gte"
    LT = "lt"
    LTE = "lte"
    EQ = "eq"
    NEQ = "neq"
    IN = "in"
    NOT_IN = "not_in"
    CONTAINS = "contains"
    NOT_CONTAINS = "not_contains"
    REGEX = "regex"
    ABSENT = "absent"
    CHANGE_PCT = "change_pct"
    ZSCORE_GT = "zscore_gt"


class RuleType(StrEnum):
    """Evaluation strategy for an alerting or detection rule."""

    THRESHOLD = "threshold"
    ANOMALY = "anomaly"
    RATE_OF_CHANGE = "rate_of_change"
    COMPOSITE = "composite"
    ABSENCE = "absence"
    LOG_PATTERN = "log_pattern"
    SNMP_TRAP = "snmp_trap"
    SYNTHETIC = "synthetic"
    SLO_BURN_RATE = "slo_burn_rate"
    TOPOLOGY_CHANGE = "topology_change"
    COMPLIANCE_DRIFT = "compliance_drift"


class NotificationChannelType(StrEnum):
    """Outbound notification target integration types."""

    EMAIL = "email"
    SLACK = "slack"
    PAGERDUTY = "pagerduty"
    OPSGENIE = "opsgenie"
    MS_TEAMS = "ms_teams"
    WEBHOOK = "webhook"
    SMS = "sms"
    TELEGRAM = "telegram"
    DISCORD = "discord"
    SERVICENOW = "servicenow"
    JIRA = "jira"
    SYSLOG_FORWARD = "syslog_forward"


class DeliveryStatus(StrEnum):
    """Delivery state for a dispatched notification or webhook message."""

    PENDING = "pending"
    QUEUED = "queued"
    SENDING = "sending"
    DELIVERED = "delivered"
    FAILED = "failed"
    RETRYING = "retrying"
    DROPPED = "dropped"
    RATE_LIMITED = "rate_limited"
    SKIPPED = "skipped"


class TopologyLinkType(StrEnum):
    """Classification of an edge between two nodes in the network topology graph."""

    PHYSICAL = "physical"
    LLDP = "lldp"
    CDP = "cdp"
    L2_ETHERNET = "l2_ethernet"
    L3_ROUTED = "l3_routed"
    BGP_PEERING = "bgp_peering"
    OSPF_ADJACENCY = "ospf_adjacency"
    LAG_MEMBER = "lag_member"
    TRUNK = "trunk"
    VPN_TUNNEL = "vpn_tunnel"
    MPLS = "mpls"
    WIRELESS = "wireless"
    VIRTUAL = "virtual"
    MANUAL = "manual"
    INFERRED = "inferred"


class DiscoveryProtocol(StrEnum):
    """Discovery mechanism used to enumerate devices and topology neighbors."""

    ICMP_SWEEP = "icmp_sweep"
    ARP = "arp"
    SNMP = "snmp"
    LLDP = "lldp"
    CDP = "cdp"
    NDP = "ndp"
    BGP = "bgp"
    OSPF = "ospf"
    DNS_AXFR = "dns_axfr"
    CLOUD_API = "cloud_api"
    KUBERNETES = "kubernetes"
    VMWARE_VCENTER = "vmware_vcenter"
    NETBOX_SYNC = "netbox_sync"


class DiscoveryJobStatus(StrEnum):
    """Execution status of a network discovery scan job."""

    PENDING = "pending"
    QUEUED = "queued"
    RUNNING = "running"
    PAUSED = "paused"
    COMPLETED = "completed"
    PARTIAL = "partial"
    FAILED = "failed"
    CANCELLED = "cancelled"


class ComplianceStatus(StrEnum):
    """Evaluation outcome of a device or config against a compliance control."""

    COMPLIANT = "compliant"
    NON_COMPLIANT = "non_compliant"
    WARNING = "warning"
    EXEMPT = "exempt"
    NOT_APPLICABLE = "not_applicable"
    ERROR = "error"
    PENDING = "pending"


class ComplianceFramework(StrEnum):
    """Industry security and network hardening compliance standards."""

    CIS_BENCHMARK = "cis_benchmark"
    PCI_DSS = "pci_dss"
    HIPAA = "hipaa"
    SOC2 = "soc2"
    ISO_27001 = "iso_27001"
    NIST_800_53 = "nist_800_53"
    NIST_CSF = "nist_csf"
    DISA_STIG = "disa_stig"
    GDPR = "gdpr"
    NERC_CIP = "nerc_cip"
    CUSTOM = "custom"


class PlaybookTriggerType(StrEnum):
    """Event source capable of initiating an automated remediation playbook."""

    MANUAL = "manual"
    ALERT_FIRED = "alert_fired"
    ALERT_RESOLVED = "alert_resolved"
    INCIDENT_CREATED = "incident_created"
    SCHEDULED = "scheduled"
    WEBHOOK = "webhook"
    COMPLIANCE_VIOLATION = "compliance_violation"
    DEVICE_DOWN = "device_down"
    INTERFACE_FLAP = "interface_flap"
    CONFIG_DRIFT = "config_drift"


class PlaybookRunStatus(StrEnum):
    """Execution status of an automation playbook run."""

    PENDING = "pending"
    AWAITING_APPROVAL = "awaiting_approval"
    RUNNING = "running"
    SUCCEEDED = "succeeded"
    PARTIAL_SUCCESS = "partial_success"
    FAILED = "failed"
    TIMED_OUT = "timed_out"
    CANCELLED = "cancelled"
    ROLLED_BACK = "rolled_back"


class ReportFormat(StrEnum):
    """Output rendering format for scheduled and ad-hoc reports."""

    PDF = "pdf"
    CSV = "csv"
    JSON = "json"
    HTML = "html"
    XLSX = "xlsx"
    MARKDOWN = "markdown"


class ReportScheduleType(StrEnum):
    """Recurrence cadence for automated report generation."""

    ONCE = "once"
    HOURLY = "hourly"
    DAILY = "daily"
    WEEKLY = "weekly"
    BIWEEKLY = "biweekly"
    MONTHLY = "monthly"
    QUARTERLY = "quarterly"
    CRON = "cron"


class AgentStatus(StrEnum):
    """Health and lifecycle state of a remote collector or satellite agent."""

    ONLINE = "online"
    OFFLINE = "offline"
    DEGRADED = "degraded"
    REGISTERING = "registering"
    UPDATING = "updating"
    DRAINING = "draining"
    REVOKED = "revoked"
    UNKNOWN = "unknown"


class SloTargetType(StrEnum):
    """Service Level Indicator (SLI) dimension measured by an SLO."""

    AVAILABILITY = "availability"
    LATENCY = "latency"
    PACKET_LOSS = "packet_loss"
    ERROR_RATE = "error_rate"
    THROUGHPUT = "throughput"
    JITTER = "jitter"
    SYNTHETIC_SUCCESS = "synthetic_success"
    CUSTOM_METRIC = "custom_metric"


class SyslogFacility(StrEnum):
    """RFC 5424 syslog facility identifiers (codes 0..23)."""

    KERN = "kern"
    USER = "user"
    MAIL = "mail"
    DAEMON = "daemon"
    AUTH = "auth"
    SYSLOG = "syslog"
    LPR = "lpr"
    NEWS = "news"
    UUCP = "uucp"
    CRON = "cron"
    AUTHPRIV = "authpriv"
    FTP = "ftp"
    NTP = "ntp"
    AUDIT = "audit"
    ALERT = "alert"
    CLOCK = "clock"
    LOCAL0 = "local0"
    LOCAL1 = "local1"
    LOCAL2 = "local2"
    LOCAL3 = "local3"
    LOCAL4 = "local4"
    LOCAL5 = "local5"
    LOCAL6 = "local6"
    LOCAL7 = "local7"

    @property
    def code(self) -> int:
        """Return the RFC 5424 numeric facility code (0..23)."""
        return _SYSLOG_FACILITY_TO_CODE[self]

    @classmethod
    def from_code(cls, code: int) -> SyslogFacility:
        """Resolve an RFC 5424 facility integer to its enum member."""
        return _SYSLOG_CODE_TO_FACILITY.get(code, cls.USER)


_SYSLOG_FACILITY_TO_CODE: dict[SyslogFacility, int] = {
    facility: idx for idx, facility in enumerate(SyslogFacility)
}
_SYSLOG_CODE_TO_FACILITY: dict[int, SyslogFacility] = {
    idx: facility for facility, idx in _SYSLOG_FACILITY_TO_CODE.items()
}


class SyslogSeverity(StrEnum):
    """RFC 5424 syslog severity levels (codes 0..7, lower is more severe)."""

    EMERGENCY = "emergency"
    ALERT = "alert"
    CRITICAL = "critical"
    ERROR = "error"
    WARNING = "warning"
    NOTICE = "notice"
    INFORMATIONAL = "informational"
    DEBUG = "debug"

    @property
    def code(self) -> int:
        """Return the RFC 5424 numeric severity code (0=emerg .. 7=debug)."""
        return _SYSLOG_SEVERITY_TO_CODE[self]

    @classmethod
    def from_code(cls, code: int) -> SyslogSeverity:
        """Resolve an RFC 5424 severity integer (0..7) to its enum member."""
        return _SYSLOG_CODE_TO_SEVERITY.get(code, cls.INFORMATIONAL)

    def to_alert_severity(self) -> AlertSeverity:
        """Map this syslog severity to the nearest :class:`AlertSeverity`."""
        mapping: dict[SyslogSeverity, AlertSeverity] = {
            SyslogSeverity.EMERGENCY: AlertSeverity.EMERGENCY,
            SyslogSeverity.ALERT: AlertSeverity.CRITICAL,
            SyslogSeverity.CRITICAL: AlertSeverity.CRITICAL,
            SyslogSeverity.ERROR: AlertSeverity.HIGH,
            SyslogSeverity.WARNING: AlertSeverity.WARNING,
            SyslogSeverity.NOTICE: AlertSeverity.LOW,
            SyslogSeverity.INFORMATIONAL: AlertSeverity.INFO,
            SyslogSeverity.DEBUG: AlertSeverity.INFO,
        }
        return mapping[self]


_SYSLOG_SEVERITY_TO_CODE: dict[SyslogSeverity, int] = {
    severity: idx for idx, severity in enumerate(SyslogSeverity)
}
_SYSLOG_CODE_TO_SEVERITY: dict[int, SyslogSeverity] = {
    idx: severity for severity, idx in _SYSLOG_SEVERITY_TO_CODE.items()
}


def parse_enum(enum_cls: type[E], raw: str | E, *, default: E | None = None) -> E:
    """Safely parse a string or enum value into *enum_cls*.

    Raises :class:`ValueError` if *raw* does not match any value and *default*
    is not provided.
    """
    if isinstance(raw, enum_cls):
        return raw
    normalized = raw.strip().lower()
    try:
        return enum_cls(normalized)
    except ValueError:
        if default is not None:
            return default
        valid = ", ".join(member.value for member in enum_cls)
        raise ValueError(
            f"Invalid value {raw!r} for {enum_cls.__name__}; expected one of: {valid}"
        ) from None


def enum_values(enum_cls: type[StrEnum]) -> list[str]:
    """Return all canonical string values declared on *enum_cls*."""
    return [member.value for member in enum_cls]


__all__ = [
    "AgentStatus",
    "AlertSeverity",
    "AlertStatus",
    "AuditAction",
    "ComplianceFramework",
    "ComplianceStatus",
    "CredentialType",
    "DeliveryStatus",
    "DeviceStatus",
    "DeviceType",
    "DeviceVendor",
    "DiscoveryJobStatus",
    "DiscoveryProtocol",
    "DuplexMode",
    "IncidentPriority",
    "IncidentStatus",
    "InterfaceStatus",
    "InterfaceType",
    "NotificationChannelType",
    "PlaybookRunStatus",
    "PlaybookTriggerType",
    "ProtocolType",
    "ReportFormat",
    "ReportScheduleType",
    "RuleOperator",
    "RuleType",
    "SloTargetType",
    "SnmpAuthProtocol",
    "SnmpPrivProtocol",
    "SnmpVersion",
    "SyslogFacility",
    "SyslogSeverity",
    "TopologyLinkType",
    "UserRole",
    "enum_values",
    "parse_enum",
]
