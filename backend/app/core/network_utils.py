"""Networking utilities: IP/CIDR math, MAC/OUI lookup, SNMP OIDs, ports, and telemetry formatting.

Production-grade network engineering toolkit for NetPulse:
- IPv4 & IPv6 validation, normalization, classification (RFC1918, CGNAT, multicast,
  loopback, link-local, ULA, documentation, public), sorting, and PTR generation.
- Full CIDR subnet calculator: network/broadcast/wildcard masks, RFC 3021 /31 & /32
  usable host math, supernetting, CIDR summarization, subnet splitting, VLSM
  allocation, and overlap/containment detection.
- MAC address parser/formatter (colon, hyphen, Cisco dotted, bare) + IEEE EUI-64
  conversion + 165+ real networking & server hardware IEEE OUI vendor prefixes.
- SNMP OID validator, normalizer, MIB alias resolver, prefix-tree matcher, and
  common MIB-2 / IF-MIB / BGP / LLDP / Host-Resources OID registry.
- Well-known TCP/UDP port registry (110+ services) with protocol & category metadata.
- Bandwidth (bps/Gbps), bytes, PPS, latency, jitter, packet loss, SNMP TimeTicks,
  uptime formatting, and 32/64-bit counter wrap utilization math.
"""

from __future__ import annotations

import ipaddress
import re
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass
from typing import Any, Literal

from app.core.exceptions import ValidationError

IPAddress = ipaddress.IPv4Address | ipaddress.IPv6Address
IPNetwork = ipaddress.IPv4Network | ipaddress.IPv6Network

# ---------------------------------------------------------------------------
# IPv4 / IPv6 validation & classification
# ---------------------------------------------------------------------------

_RFC1918_NETWORKS: tuple[ipaddress.IPv4Network, ...] = (
    ipaddress.IPv4Network("10.0.0.0/8"),
    ipaddress.IPv4Network("172.16.0.0/12"),
    ipaddress.IPv4Network("192.168.0.0/16"),
)
_CGNAT_NETWORK = ipaddress.IPv4Network("100.64.0.0/10")  # RFC 6598
_BENCHMARK_V4 = ipaddress.IPv4Network("198.18.0.0/15")  # RFC 2544
_DOCUMENTATION_V4: tuple[ipaddress.IPv4Network, ...] = (
    ipaddress.IPv4Network("192.0.2.0/24"),
    ipaddress.IPv4Network("198.51.100.0/24"),
    ipaddress.IPv4Network("203.0.113.0/24"),
)
_DOCUMENTATION_V6 = ipaddress.IPv6Network("2001:db8::/32")
_ULA_V6 = ipaddress.IPv6Network("fc00::/7")  # RFC 4193


def is_valid_ip(value: str) -> bool:
    """Return True if ``value`` is a syntactically valid IPv4 or IPv6 address."""
    if not isinstance(value, str):
        return False
    try:
        ipaddress.ip_address(value.strip())
        return True
    except ValueError:
        return False


def is_valid_ipv4(value: str) -> bool:
    """Return True if ``value`` is a valid IPv4 address."""
    if not isinstance(value, str):
        return False
    try:
        ipaddress.IPv4Address(value.strip())
        return True
    except ValueError:
        return False


def is_valid_ipv6(value: str) -> bool:
    """Return True if ``value`` is a valid IPv6 address."""
    if not isinstance(value, str):
        return False
    try:
        ipaddress.IPv6Address(value.strip())
        return True
    except ValueError:
        return False


def is_valid_cidr(value: str, *, strict: bool = False) -> bool:
    """Return True if ``value`` is a valid IPv4 or IPv6 CIDR block."""
    if not isinstance(value, str) or "/" not in value:
        return False
    try:
        ipaddress.ip_network(value.strip(), strict=strict)
        return True
    except ValueError:
        return False


def parse_ip(value: str) -> IPAddress:
    """Parse an IPv4 or IPv6 address string or raise :class:`ValidationError`."""
    try:
        return ipaddress.ip_address(value.strip())
    except (ValueError, AttributeError) as exc:
        raise ValidationError(f"Invalid IP address: {value!r}", details={"ip": value}) from exc


def parse_network(value: str, *, strict: bool = False) -> IPNetwork:
    """Parse an IPv4 or IPv6 CIDR string or raise :class:`ValidationError`."""
    try:
        return ipaddress.ip_network(value.strip(), strict=strict)
    except (ValueError, AttributeError) as exc:
        raise ValidationError(f"Invalid CIDR network: {value!r}", details={"cidr": value}) from exc


def normalize_ip(value: str) -> str:
    """Return the canonical compressed representation of an IPv4/IPv6 address."""
    return str(parse_ip(value))


def ip_to_int(value: str) -> int:
    """Convert an IPv4 or IPv6 address to its unsigned integer representation."""
    return int(parse_ip(value))


def int_to_ip(number: int, *, version: Literal[4, 6] = 4) -> str:
    """Convert an unsigned integer to its canonical IPv4 or IPv6 string."""
    try:
        if version == 4:
            return str(ipaddress.IPv4Address(number))
        return str(ipaddress.IPv6Address(number))
    except ValueError as exc:
        raise ValidationError(
            f"Integer {number} out of range for IPv{version}",
            details={"value": number, "version": version},
        ) from exc


def sort_ips(ips: Iterable[str]) -> list[str]:
    """Sort mixed IPv4 and IPv6 addresses numerically (IPv4 first, then IPv6)."""
    parsed = [parse_ip(ip) for ip in ips]
    parsed.sort(key=lambda addr: (addr.version, int(addr)))
    return [str(addr) for addr in parsed]


def reverse_dns_pointer(ip_str: str) -> str:
    """Return the reverse DNS PTR domain (``in-addr.arpa`` / ``ip6.arpa``)."""
    return parse_ip(ip_str).reverse_pointer


def is_rfc1918(ip_str: str) -> bool:
    """Return True if ``ip_str`` is an IPv4 address in RFC 1918 private space."""
    addr = parse_ip(ip_str)
    if isinstance(addr, ipaddress.IPv6Address):
        if addr.ipv4_mapped is None:
            return False
        addr = addr.ipv4_mapped
    return any(addr in net for net in _RFC1918_NETWORKS)


def is_cgnat(ip_str: str) -> bool:
    """Return True if ``ip_str`` falls in RFC 6598 Shared Address Space (100.64.0.0/10)."""
    addr = parse_ip(ip_str)
    return isinstance(addr, ipaddress.IPv4Address) and addr in _CGNAT_NETWORK


@dataclass(frozen=True)
class IPClassification:
    """Detailed address-space classification for an IPv4 or IPv6 address."""

    ip: str
    version: int
    scope: str
    is_private: bool
    is_global: bool
    is_rfc1918: bool
    is_cgnat: bool
    is_loopback: bool
    is_link_local: bool
    is_multicast: bool
    is_reserved: bool
    is_unspecified: bool
    is_documentation: bool
    is_ula: bool

    def to_dict(self) -> dict[str, Any]:
        return {
            "ip": self.ip,
            "version": self.version,
            "scope": self.scope,
            "is_private": self.is_private,
            "is_global": self.is_global,
            "is_rfc1918": self.is_rfc1918,
            "is_cgnat": self.is_cgnat,
            "is_loopback": self.is_loopback,
            "is_link_local": self.is_link_local,
            "is_multicast": self.is_multicast,
            "is_reserved": self.is_reserved,
            "is_unspecified": self.is_unspecified,
            "is_documentation": self.is_documentation,
            "is_ula": self.is_ula,
        }


def classify_ip(ip_str: str) -> IPClassification:
    """Classify an IPv4 or IPv6 address into RFC address-space categories."""
    addr = parse_ip(ip_str)
    rfc1918 = isinstance(addr, ipaddress.IPv4Address) and any(addr in n for n in _RFC1918_NETWORKS)
    cgnat = isinstance(addr, ipaddress.IPv4Address) and addr in _CGNAT_NETWORK
    ula = isinstance(addr, ipaddress.IPv6Address) and addr in _ULA_V6
    is_doc = (
        any(addr in n for n in _DOCUMENTATION_V4)
        if isinstance(addr, ipaddress.IPv4Address)
        else addr in _DOCUMENTATION_V6
    )
    is_benchmark = isinstance(addr, ipaddress.IPv4Address) and addr in _BENCHMARK_V4

    if addr.is_unspecified:
        scope = "unspecified"
    elif addr.is_loopback:
        scope = "loopback"
    elif addr.is_multicast:
        scope = "multicast"
    elif addr.is_link_local:
        scope = "link_local"
    elif is_doc:
        scope = "documentation"
    elif is_benchmark:
        scope = "benchmark"
    elif cgnat:
        scope = "cgnat"
    elif rfc1918:
        scope = "rfc1918_private"
    elif ula:
        scope = "ipv6_ula"
    elif addr.is_private:
        scope = "private"
    elif addr.is_reserved:
        scope = "reserved"
    elif addr.is_global:
        scope = "public"
    else:
        scope = "special"

    return IPClassification(
        ip=str(addr),
        version=addr.version,
        scope=scope,
        is_private=addr.is_private,
        is_global=addr.is_global and not is_doc and not cgnat,
        is_rfc1918=rfc1918,
        is_cgnat=cgnat,
        is_loopback=addr.is_loopback,
        is_link_local=addr.is_link_local,
        is_multicast=addr.is_multicast,
        is_reserved=addr.is_reserved,
        is_unspecified=addr.is_unspecified,
        is_documentation=is_doc,
        is_ula=ula,
    )


# ---------------------------------------------------------------------------
# CIDR Subnet Calculator, Splitting, Supernetting, VLSM & Overlap Detection
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class SubnetInfo:
    """Computed subnet geometry and metadata for an IPv4 or IPv6 CIDR."""

    cidr: str
    version: int
    network_address: str
    broadcast_address: str | None
    netmask: str
    hostmask: str
    prefix_length: int
    total_addresses: int
    usable_hosts: int
    first_usable: str | None
    last_usable: str | None
    scope: str
    is_private: bool
    is_rfc1918: bool
    binary_netmask: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "cidr": self.cidr,
            "version": self.version,
            "network_address": self.network_address,
            "broadcast_address": self.broadcast_address,
            "netmask": self.netmask,
            "hostmask": self.hostmask,
            "prefix_length": self.prefix_length,
            "total_addresses": self.total_addresses,
            "usable_hosts": self.usable_hosts,
            "first_usable": self.first_usable,
            "last_usable": self.last_usable,
            "scope": self.scope,
            "is_private": self.is_private,
            "is_rfc1918": self.is_rfc1918,
            "binary_netmask": self.binary_netmask,
        }


def calculate_subnet(cidr: str, *, strict: bool = False) -> SubnetInfo:
    """Calculate comprehensive subnet attributes for an IPv4 or IPv6 CIDR block."""
    net = parse_network(cidr, strict=strict)
    classification = classify_ip(str(net.network_address))
    total = net.num_addresses

    if isinstance(net, ipaddress.IPv4Network):
        binary_mask = ".".join(f"{octet:08b}" for octet in net.netmask.packed)
        if net.prefixlen == 32:
            usable = 1
            first_u = str(net.network_address)
            last_u = str(net.network_address)
            bcast: str | None = None
        elif net.prefixlen == 31:
            # RFC 3021 point-to-point link: both addresses are usable
            usable = 2
            first_u = str(net.network_address)
            last_u = str(net.broadcast_address)
            bcast = None
        else:
            usable = max(0, total - 2)
            first_u = str(net.network_address + 1)
            last_u = str(net.broadcast_address - 1)
            bcast = str(net.broadcast_address)
    else:
        binary_mask = None
        bcast = None
        if net.prefixlen == 128:
            usable = 1
            first_u = str(net.network_address)
            last_u = str(net.network_address)
        elif net.prefixlen == 127:
            usable = 2
            first_u = str(net.network_address)
            last_u = str(net.broadcast_address)
        else:
            usable = total
            first_u = str(net.network_address)
            last_u = str(net.broadcast_address)

    return SubnetInfo(
        cidr=str(net),
        version=net.version,
        network_address=str(net.network_address),
        broadcast_address=bcast,
        netmask=str(net.netmask),
        hostmask=str(net.hostmask),
        prefix_length=net.prefixlen,
        total_addresses=total,
        usable_hosts=usable,
        first_usable=first_u,
        last_usable=last_u,
        scope=classification.scope,
        is_private=classification.is_private,
        is_rfc1918=classification.is_rfc1918,
        binary_netmask=binary_mask,
    )


def split_subnet(
    cidr: str,
    *,
    new_prefix: int | None = None,
    count: int | None = None,
    max_results: int = 4096,
) -> list[str]:
    """Split a CIDR into equal-sized child subnets by ``new_prefix`` or ``count``."""
    net = parse_network(cidr)
    if new_prefix is None and count is None:
        new_prefix = net.prefixlen + 1
    elif count is not None:
        if count < 1:
            raise ValidationError("Subnet split count must be >= 1")
        prefix_diff = (count - 1).bit_length()
        new_prefix = net.prefixlen + prefix_diff

    assert new_prefix is not None
    if new_prefix < net.prefixlen or new_prefix > net.max_prefixlen:
        raise ValidationError(
            f"Target prefix /{new_prefix} invalid for {net}",
            details={"cidr": str(net), "new_prefix": new_prefix},
        )
    total_children = 1 << (new_prefix - net.prefixlen)
    if total_children > max_results:
        raise ValidationError(
            f"Subnet split produces {total_children} subnets, exceeding limit {max_results}",
            details={"total_children": total_children, "max_results": max_results},
        )
    return [str(sub) for sub in net.subnets(new_prefix=new_prefix)]


def calculate_supernet(cidr: str, new_prefix: int) -> str:
    """Return the enclosing supernet of ``cidr`` at ``new_prefix``."""
    net = parse_network(cidr)
    if new_prefix < 0 or new_prefix > net.prefixlen:
        raise ValidationError(
            f"Supernet prefix /{new_prefix} must be between 0 and /{net.prefixlen}",
            details={"cidr": str(net), "new_prefix": new_prefix},
        )
    return str(net.supernet(new_prefix=new_prefix))


def summarize_cidrs(cidrs: Sequence[str]) -> list[str]:
    """Collapse and aggregate contiguous/overlapping IPv4 and IPv6 CIDRs."""
    v4: list[ipaddress.IPv4Network] = []
    v6: list[ipaddress.IPv6Network] = []
    for raw in cidrs:
        net = parse_network(raw)
        if isinstance(net, ipaddress.IPv4Network):
            v4.append(net)
        else:
            v6.append(net)
    result = [str(n) for n in ipaddress.collapse_addresses(v4)]
    result.extend(str(n) for n in ipaddress.collapse_addresses(v6))
    return result


def allocate_vlsm(base_cidr: str, requirements: Mapping[str, int]) -> dict[str, str]:
    """Allocate Variable-Length Subnet Masks (VLSM) inside ``base_cidr``.

    Args:
        base_cidr: Enclosing IPv4 CIDR block.
        requirements: Mapping of segment name -> required usable host count.

    Returns:
        Mapping of segment name -> allocated CIDR string.
    """
    base = parse_network(base_cidr)
    if not isinstance(base, ipaddress.IPv4Network):
        raise ValidationError("VLSM allocation currently supports IPv4 CIDR blocks")

    # Allocate largest subnets first to avoid fragmentation
    ordered = sorted(requirements.items(), key=lambda kv: kv[1], reverse=True)
    free_blocks: list[ipaddress.IPv4Network] = [base]
    allocations: dict[str, str] = {}

    for name, hosts_needed in ordered:
        if hosts_needed < 1:
            raise ValidationError(f"Host requirement for {name!r} must be >= 1")
        if hosts_needed == 1:
            needed_prefix = 32
        elif hosts_needed == 2:
            needed_prefix = 30  # standard subnet with network + broadcast + 2 hosts
        else:
            host_bits = (hosts_needed + 2 - 1).bit_length()
            needed_prefix = 32 - host_bits
        if needed_prefix < base.prefixlen:
            raise ValidationError(
                f"Requirement {name!r} ({hosts_needed} hosts) exceeds base block {base}"
            )

        free_blocks.sort(key=lambda b: (-b.prefixlen, int(b.network_address)))
        chosen_idx: int | None = None
        for idx, block in enumerate(free_blocks):
            if block.prefixlen <= needed_prefix:
                chosen_idx = idx
                break
        if chosen_idx is None:
            raise ValidationError(
                f"Insufficient address space in {base} to allocate {name!r} (/{needed_prefix})"
            )

        block = free_blocks.pop(chosen_idx)
        while block.prefixlen < needed_prefix:
            left, right = list(block.subnets(prefixlen_diff=1))
            free_blocks.append(right)
            block = left
        allocations[name] = str(block)

    return allocations


def ip_in_cidr(ip_str: str, cidr: str) -> bool:
    """Return True if ``ip_str`` belongs to ``cidr``."""
    addr = parse_ip(ip_str)
    net = parse_network(cidr)
    return addr.version == net.version and addr in net


def subnet_contains(parent_cidr: str, child_cidr: str) -> bool:
    """Return True if ``child_cidr`` is a subnet of (or equal to) ``parent_cidr``."""
    parent = parse_network(parent_cidr)
    child = parse_network(child_cidr)
    return parent.version == child.version and child.subnet_of(parent)  # type: ignore[arg-type]


def cidrs_overlap(cidr_a: str, cidr_b: str) -> bool:
    """Return True if two CIDR blocks share at least one IP address."""
    net_a = parse_network(cidr_a)
    net_b = parse_network(cidr_b)
    return net_a.version == net_b.version and net_a.overlaps(net_b)


def find_overlapping_cidrs(cidrs: Sequence[str]) -> list[tuple[str, str]]:
    """Return all pairs of overlapping CIDR blocks from ``cidrs``."""
    parsed = [(raw, parse_network(raw)) for raw in cidrs]
    overlaps: list[tuple[str, str]] = []
    for i in range(len(parsed)):
        raw_a, net_a = parsed[i]
        for j in range(i + 1, len(parsed)):
            raw_b, net_b = parsed[j]
            if net_a.version == net_b.version and net_a.overlaps(net_b):
                overlaps.append((raw_a, raw_b))
    return overlaps


# ---------------------------------------------------------------------------
# MAC Address Parsing, Formatting, EUI-64 & IEEE OUI Vendor Registry (165+)
# ---------------------------------------------------------------------------

_MAC_FORMAT_REGEXES: tuple[re.Pattern[str], ...] = (
    re.compile(r"^[0-9a-fA-F]{2}(?::[0-9a-fA-F]{2}){5}$"),  # 00:1a:2b:3c:4d:5e
    re.compile(r"^[0-9a-fA-F]{2}(?:-[0-9a-fA-F]{2}){5}$"),  # 00-1a-2b-3c-4d-5e
    re.compile(r"^[0-9a-fA-F]{4}(?:\.[0-9a-fA-F]{4}){2}$"),  # 001a.2b3c.4d5e (Cisco)
    re.compile(r"^[0-9a-fA-F]{12}$"),  # 001a2b3c4d5e
    re.compile(r"^[0-9a-fA-F]{2}(?:\s+[0-9a-fA-F]{2}){5}$"),  # 00 1a 2b 3c 4d 5e
)


def is_valid_mac(mac: str) -> bool:
    """Return True if ``mac`` matches colon, hyphen, Cisco dotted, bare, or space format."""
    if not isinstance(mac, str):
        return False
    cleaned = mac.strip()
    return any(rx.match(cleaned) is not None for rx in _MAC_FORMAT_REGEXES)


def parse_mac(mac: str) -> bytes:
    """Parse any standard MAC format into its raw 6-byte representation."""
    if not is_valid_mac(mac):
        raise ValidationError(f"Invalid MAC address: {mac!r}", details={"mac": mac})
    hex_digits = re.sub(r"[^0-9a-fA-F]", "", mac)
    return bytes.fromhex(hex_digits)


def format_mac(
    mac: str,
    *,
    style: Literal["colon", "hyphen", "cisco", "bare"] = "colon",
    uppercase: bool = False,
) -> str:
    """Format a MAC address into ``colon``, ``hyphen``, ``cisco``, or ``bare`` style."""
    raw = parse_mac(mac)
    hex_str = raw.hex().upper() if uppercase else raw.hex().lower()
    if style == "colon":
        return ":".join(hex_str[i : i + 2] for i in range(0, 12, 2))
    if style == "hyphen":
        return "-".join(hex_str[i : i + 2] for i in range(0, 12, 2))
    if style == "cisco":
        return ".".join(hex_str[i : i + 4] for i in range(0, 12, 4))
    if style == "bare":
        return hex_str
    raise ValidationError(f"Unsupported MAC format style: {style!r}")


def get_oui(mac: str) -> str:
    """Extract the uppercase colon-separated 24-bit OUI prefix (``XX:XX:XX``)."""
    raw = parse_mac(mac)
    return ":".join(f"{b:02X}" for b in raw[:3])


def is_broadcast_mac(mac: str) -> bool:
    return parse_mac(mac) == b"\xff\xff\xff\xff\xff\xff"


def is_multicast_mac(mac: str) -> bool:
    return bool(parse_mac(mac)[0] & 0x01)


def is_locally_administered_mac(mac: str) -> bool:
    return bool(parse_mac(mac)[0] & 0x02)


def mac_to_eui64(mac: str, *, ipv6_prefix: str = "fe80::") -> str:
    """Derive a modified IEEE EUI-64 IPv6 address from a 48-bit MAC and /64 prefix."""
    raw = parse_mac(mac)
    eui = bytearray([raw[0] ^ 0x02, raw[1], raw[2], 0xFF, 0xFE, raw[3], raw[4], raw[5]])
    prefix_net = parse_network(f"{ipv6_prefix.rstrip('/')}/64")
    if not isinstance(prefix_net, ipaddress.IPv6Network):
        raise ValidationError("EUI-64 requires an IPv6 prefix")
    prefix_int = int(prefix_net.network_address) & (~((1 << 64) - 1))
    iid_int = int.from_bytes(eui, "big")
    return str(ipaddress.IPv6Address(prefix_int | iid_int))


# Real-world IEEE OUI Vendor Prefix Registry (165+ entries across major network/server vendors)
OUI_VENDOR_TABLE: dict[str, str] = {
    # Cisco Systems
    "00:00:0C": "Cisco Systems",
    "00:01:42": "Cisco Systems",
    "00:01:43": "Cisco Systems",
    "00:01:96": "Cisco Systems",
    "00:01:97": "Cisco Systems",
    "00:02:16": "Cisco Systems",
    "00:02:17": "Cisco Systems",
    "00:0B:BE": "Cisco Systems",
    "00:1A:A1": "Cisco Systems",
    "00:1B:D5": "Cisco Systems",
    "00:1E:13": "Cisco Systems",
    "00:1E:F7": "Cisco Systems",
    "00:26:0B": "Cisco Systems",
    "00:50:0F": "Cisco Systems",
    "00:D0:BA": "Cisco Systems",
    "04:DA:D2": "Cisco Systems",
    "1C:DF:0F": "Cisco Systems",
    "2C:31:24": "Cisco Systems",
    "3C:CE:73": "Cisco Systems",
    "58:AC:78": "Cisco Systems",
    "68:BD:AB": "Cisco Systems",
    "70:DB:98": "Cisco Systems",
    "88:5A:92": "Cisco Systems",
    "A4:6C:2A": "Cisco Systems",
    "CC:46:D6": "Cisco Systems",
    "F4:CF:E2": "Cisco Systems",
    # Cisco Meraki
    "00:18:0A": "Cisco Meraki",
    "0C:8D:DB": "Cisco Meraki",
    "34:56:FE": "Cisco Meraki",
    "88:15:44": "Cisco Meraki",
    "AC:17:C8": "Cisco Meraki",
    "E0:55:3D": "Cisco Meraki",
    # Juniper Networks
    "00:05:85": "Juniper Networks",
    "00:10:DB": "Juniper Networks",
    "00:12:1E": "Juniper Networks",
    "00:14:F6": "Juniper Networks",
    "00:17:CB": "Juniper Networks",
    "00:19:E2": "Juniper Networks",
    "00:1B:C0": "Juniper Networks",
    "00:21:59": "Juniper Networks",
    "00:23:9C": "Juniper Networks",
    "00:26:88": "Juniper Networks",
    "28:8A:1C": "Juniper Networks",
    "3C:61:04": "Juniper Networks",
    "50:C5:8D": "Juniper Networks",
    "84:B5:9C": "Juniper Networks",
    "AC:4B:C8": "Juniper Networks",
    "EC:38:73": "Juniper Networks",
    # Arista Networks
    "00:1C:73": "Arista Networks",
    "28:99:3A": "Arista Networks",
    "44:4C:A8": "Arista Networks",
    "74:83:EF": "Arista Networks",
    "94:8E:D3": "Arista Networks",
    "C0:D6:82": "Arista Networks",
    "FC:BD:67": "Arista Networks",
    # MikroTik (Routerboard)
    "00:0C:42": "MikroTik",
    "08:55:31": "MikroTik",
    "18:FD:74": "MikroTik",
    "2C:C8:1B": "MikroTik",
    "48:8F:5A": "MikroTik",
    "4C:5E:0C": "MikroTik",
    "64:D1:54": "MikroTik",
    "6C:3B:6B": "MikroTik",
    "74:4D:28": "MikroTik",
    "B8:69:F4": "MikroTik",
    "CC:2D:E0": "MikroTik",
    "D4:01:C3": "MikroTik",
    "DC:2C:6E": "MikroTik",
    "E4:8D:8C": "MikroTik",
    # Ubiquiti Inc.
    "00:15:6D": "Ubiquiti Networks",
    "00:27:22": "Ubiquiti Networks",
    "04:18:D6": "Ubiquiti Networks",
    "18:E8:29": "Ubiquiti Networks",
    "24:5A:4C": "Ubiquiti Networks",
    "24:A4:3C": "Ubiquiti Networks",
    "44:D9:E7": "Ubiquiti Networks",
    "68:72:51": "Ubiquiti Networks",
    "70:A7:41": "Ubiquiti Networks",
    "74:83:C2": "Ubiquiti Networks",
    "78:8A:20": "Ubiquiti Networks",
    "80:2A:A8": "Ubiquiti Networks",
    "B4:FB:E4": "Ubiquiti Networks",
    "DC:9F:DB": "Ubiquiti Networks",
    "E0:63:DA": "Ubiquiti Networks",
    "F0:9F:C2": "Ubiquiti Networks",
    "FC:EC:DA": "Ubiquiti Networks",
    # Palo Alto Networks
    "00:1B:17": "Palo Alto Networks",
    "00:86:9C": "Palo Alto Networks",
    "08:30:6B": "Palo Alto Networks",
    "58:49:3B": "Palo Alto Networks",
    "7C:89:C1": "Palo Alto Networks",
    "B4:0C:25": "Palo Alto Networks",
    "D4:F4:BE": "Palo Alto Networks",
    # Fortinet
    "00:09:0F": "Fortinet",
    "08:5B:0E": "Fortinet",
    "70:4C:A5": "Fortinet",
    "90:6C:AC": "Fortinet",
    "D4:76:A0": "Fortinet",
    "E8:1C:BA": "Fortinet",
    # HPE / Aruba Networks
    "00:0B:86": "Aruba Networks (HPE)",
    "00:1A:1E": "Aruba Networks (HPE)",
    "00:24:6C": "Aruba Networks (HPE)",
    "20:4C:03": "Aruba Networks (HPE)",
    "24:DE:C6": "Aruba Networks (HPE)",
    "40:E3:D6": "Aruba Networks (HPE)",
    "6C:F3:7F": "Aruba Networks (HPE)",
    "9C:1C:12": "Aruba Networks (HPE)",
    "AC:A3:1E": "Aruba Networks (HPE)",
    "00:17:A4": "Hewlett Packard Enterprise",
    "00:1E:0B": "Hewlett Packard Enterprise",
    "00:25:B3": "Hewlett Packard Enterprise",
    "3C:D9:2B": "Hewlett Packard Enterprise",
    "94:57:A5": "Hewlett Packard Enterprise",
    "EC:B1:D7": "Hewlett Packard Enterprise",
    # Dell Technologies
    "00:06:5B": "Dell Technologies",
    "00:14:22": "Dell Technologies",
    "00:1E:C9": "Dell Technologies",
    "14:18:77": "Dell Technologies",
    "18:03:73": "Dell Technologies",
    "24:B6:FD": "Dell Technologies",
    "54:9F:35": "Dell Technologies",
    "B0:83:FE": "Dell Technologies",
    "D4:AE:52": "Dell Technologies",
    "F8:BC:12": "Dell Technologies",
    # Huawei Technologies
    "00:18:82": "Huawei Technologies",
    "00:25:9E": "Huawei Technologies",
    "00:E0:FC": "Huawei Technologies",
    "28:6E:D4": "Huawei Technologies",
    "48:46:FB": "Huawei Technologies",
    "70:7B:E8": "Huawei Technologies",
    "88:86:03": "Huawei Technologies",
    "C8:D1:5E": "Huawei Technologies",
    "E0:24:7F": "Huawei Technologies",
    # Extreme Networks
    "00:01:30": "Extreme Networks",
    "00:04:96": "Extreme Networks",
    "00:E0:2B": "Extreme Networks",
    "B4:C7:99": "Extreme Networks",
    # Netgear
    "00:09:5B": "NETGEAR",
    "00:14:6C": "NETGEAR",
    "00:1E:2A": "NETGEAR",
    "20:4E:7F": "NETGEAR",
    "6C:B0:CE": "NETGEAR",
    "A0:40:A0": "NETGEAR",
    "C4:04:15": "NETGEAR",
    # TP-Link
    "00:23:CD": "TP-Link Technologies",
    "14:CC:20": "TP-Link Technologies",
    "50:C7:BF": "TP-Link Technologies",
    "60:E3:27": "TP-Link Technologies",
    "98:DA:C4": "TP-Link Technologies",
    "C0:25:E9": "TP-Link Technologies",
    "F4:F2:6D": "TP-Link Technologies",
    # Supermicro
    "00:25:90": "Super Micro Computer",
    "00:30:48": "Super Micro Computer",
    "0C:C4:7A": "Super Micro Computer",
    "3C:EC:EF": "Super Micro Computer",
    "AC:1F:6B": "Super Micro Computer",
    # Intel Corporation
    "00:02:B3": "Intel Corporation",
    "00:1B:21": "Intel Corporation",
    "00:1E:67": "Intel Corporation",
    "3C:FD:FE": "Intel Corporation",
    "68:05:CA": "Intel Corporation",
    "90:E2:BA": "Intel Corporation",
    "A0:36:9F": "Intel Corporation",
    "B4:96:91": "Intel Corporation",
    # VMware / Virtualization & Cloud
    "00:05:69": "VMware",
    "00:0C:29": "VMware",
    "00:1C:14": "VMware",
    "00:50:56": "VMware",
    "00:15:5D": "Microsoft Hyper-V",
    "00:16:3E": "Xen / Xensource",
    "52:54:00": "QEMU / KVM",
    "08:00:27": "Oracle VirtualBox",
    "02:42:AC": "Docker Container",
    "BC:24:11": "Proxmox Server Solutions",
    # Mellanox / NVIDIA, F5, Check Point, Ruckus, Brocade, Nokia, Ciena
    "00:02:C9": "Mellanox / NVIDIA Networking",
    "0C:42:A1": "Mellanox / NVIDIA Networking",
    "24:8A:07": "Mellanox / NVIDIA Networking",
    "B8:CE:F6": "Mellanox / NVIDIA Networking",
    "00:01:D7": "F5 Networks",
    "00:23:E9": "F5 Networks",
    "00:1C:7F": "Check Point Software",
    "00:17:C5": "SonicWall",
    "00:90:7F": "WatchGuard Technologies",
    "00:13:92": "Ruckus Wireless",
    "2C:C5:D3": "Ruckus Wireless",
    "00:05:1E": "Brocade Communications",
    "00:24:38": "Brocade Communications",
    "00:16:4D": "Nokia / Alcatel-Lucent",
    "00:23:8A": "Ciena Corporation",
    # Storage, SBC & Enterprise Servers
    "00:11:32": "Synology",
    "24:5E:BE": "QNAP Systems",
    "B8:27:EB": "Raspberry Pi Foundation",
    "DC:A6:32": "Raspberry Pi Trading",
    "E4:5F:01": "Raspberry Pi Trading",
    "00:0A:95": "Apple",
    "3C:06:30": "Apple",
    "00:10:18": "Broadcom",
    "00:E0:4C": "Realtek Semiconductor",
    "54:EE:75": "Lenovo",
    "00:09:6B": "IBM",
    "00:14:4F": "Oracle / Sun Microsystems",
}


def lookup_oui_vendor(mac: str) -> str | None:
    """Resolve the hardware vendor name from a MAC address via IEEE OUI prefix."""
    oui = get_oui(mac)
    vendor = OUI_VENDOR_TABLE.get(oui)
    if vendor is not None:
        return vendor
    if is_broadcast_mac(mac):
        return "Broadcast"
    if is_locally_administered_mac(mac):
        return "Locally Administered"
    return None


def search_oui_by_vendor(query: str) -> dict[str, str]:
    """Search the OUI table for prefixes matching a vendor substring (case-insensitive)."""
    needle = query.strip().lower()
    if not needle:
        return {}
    return {oui: vendor for oui, vendor in OUI_VENDOR_TABLE.items() if needle in vendor.lower()}


# ---------------------------------------------------------------------------
# SNMP OID Validation, Normalization, MIB Aliasing & Prefix-Tree Matcher
# ---------------------------------------------------------------------------

_OID_REGEX = re.compile(r"^\.?[0-2](?:\.(?:0|[1-9][0-9]*))*$")

COMMON_SNMP_OIDS: dict[str, str] = {
    # MIB-2 System Group
    "SNMPv2-MIB::sysDescr": "1.3.6.1.2.1.1.1",
    "SNMPv2-MIB::sysObjectID": "1.3.6.1.2.1.1.2",
    "SNMPv2-MIB::sysUpTime": "1.3.6.1.2.1.1.3",
    "SNMPv2-MIB::sysContact": "1.3.6.1.2.1.1.4",
    "SNMPv2-MIB::sysName": "1.3.6.1.2.1.1.5",
    "SNMPv2-MIB::sysLocation": "1.3.6.1.2.1.1.6",
    "SNMPv2-MIB::sysServices": "1.3.6.1.2.1.1.7",
    # IF-MIB (32-bit & 64-bit High-Capacity counters)
    "IF-MIB::ifNumber": "1.3.6.1.2.1.2.1",
    "IF-MIB::ifTable": "1.3.6.1.2.1.2.2",
    "IF-MIB::ifDescr": "1.3.6.1.2.1.2.2.1.2",
    "IF-MIB::ifType": "1.3.6.1.2.1.2.2.1.3",
    "IF-MIB::ifMtu": "1.3.6.1.2.1.2.2.1.4",
    "IF-MIB::ifSpeed": "1.3.6.1.2.1.2.2.1.5",
    "IF-MIB::ifPhysAddress": "1.3.6.1.2.1.2.2.1.6",
    "IF-MIB::ifAdminStatus": "1.3.6.1.2.1.2.2.1.7",
    "IF-MIB::ifOperStatus": "1.3.6.1.2.1.2.2.1.8",
    "IF-MIB::ifInOctets": "1.3.6.1.2.1.2.2.1.10",
    "IF-MIB::ifInDiscards": "1.3.6.1.2.1.2.2.1.13",
    "IF-MIB::ifInErrors": "1.3.6.1.2.1.2.2.1.14",
    "IF-MIB::ifOutOctets": "1.3.6.1.2.1.2.2.1.16",
    "IF-MIB::ifOutDiscards": "1.3.6.1.2.1.2.2.1.19",
    "IF-MIB::ifOutErrors": "1.3.6.1.2.1.2.2.1.20",
    "IF-MIB::ifXTable": "1.3.6.1.2.1.31.1.1",
    "IF-MIB::ifName": "1.3.6.1.2.1.31.1.1.1.1",
    "IF-MIB::ifHCInOctets": "1.3.6.1.2.1.31.1.1.1.6",
    "IF-MIB::ifHCOutOctets": "1.3.6.1.2.1.31.1.1.1.10",
    "IF-MIB::ifHighSpeed": "1.3.6.1.2.1.31.1.1.1.15",
    "IF-MIB::ifAlias": "1.3.6.1.2.1.31.1.1.1.18",
    # HOST-RESOURCES-MIB
    "HOST-RESOURCES-MIB::hrSystemUptime": "1.3.6.1.2.1.25.1.1",
    "HOST-RESOURCES-MIB::hrMemorySize": "1.3.6.1.2.1.25.2.2",
    "HOST-RESOURCES-MIB::hrStorageTable": "1.3.6.1.2.1.25.2.3",
    "HOST-RESOURCES-MIB::hrProcessorLoad": "1.3.6.1.2.1.25.3.3.1.2",
    # ENTITY-MIB, LLDP-MIB, BGP4-MIB, OSPF-MIB
    "ENTITY-MIB::entPhysicalTable": "1.3.6.1.2.1.47.1.1.1",
    "LLDP-MIB::lldpRemTable": "1.0.8802.1.1.2.1.4.1",
    "LLDP-MIB::lldpRemSysName": "1.0.8802.1.1.2.1.4.1.1.9",
    "BGP4-MIB::bgpPeerState": "1.3.6.1.2.1.15.3.1.2",
    "BGP4-MIB::bgpPeerRemoteAs": "1.3.6.1.2.1.15.3.1.9",
    "OSPF-MIB::ospfNbrState": "1.3.6.1.2.1.14.10.1.6",
    # UCD-SNMP & Cisco Enterprise MIBs
    "UCD-SNMP-MIB::laLoad": "1.3.6.1.4.1.2021.10.1.3",
    "UCD-SNMP-MIB::memAvailReal": "1.3.6.1.4.1.2021.4.6",
    "CISCO-PROCESS-MIB::cpmCPUTotal5minRev": "1.3.6.1.4.1.9.9.109.1.1.1.1.8",
    "CISCO-MEMORY-POOL-MIB::ciscoMemoryPoolUsed": "1.3.6.1.4.1.9.9.48.1.1.1.5",
}

_SHORT_OID_ALIASES: dict[str, str] = {
    name.split("::", 1)[1]: oid for name, oid in COMMON_SNMP_OIDS.items()
}
_OID_TO_MIB_NAME: dict[str, str] = {oid: name for name, oid in COMMON_SNMP_OIDS.items()}


def is_valid_oid(oid: str) -> bool:
    """Return True if ``oid`` is a valid numeric ASN.1/SNMP OID."""
    if not isinstance(oid, str):
        return False
    cleaned = oid.strip()
    if not _OID_REGEX.match(cleaned):
        return False
    arcs = [int(a) for a in cleaned.lstrip(".").split(".")]
    if len(arcs) >= 2 and arcs[0] in (0, 1) and arcs[1] >= 40:
        return False
    return len(arcs) >= 2


def normalize_oid(oid: str, *, leading_dot: bool = False) -> str:
    """Normalize an SNMP OID or MIB alias (e.g. ``IF-MIB::ifInOctets.1``) to dotted form."""
    if not isinstance(oid, str) or not oid.strip():
        raise ValidationError("SNMP OID must be a non-empty string")
    raw = oid.strip()

    # Resolve MIB::object(.suffix) or short object(.suffix) aliases
    if not raw[0].isdigit() and not raw.startswith("."):
        parts = raw.split(".", 1)
        head = parts[0]
        suffix = f".{parts[1]}" if len(parts) == 2 else ""
        base = COMMON_SNMP_OIDS.get(head) or _SHORT_OID_ALIASES.get(head)
        if base is None:
            raise ValidationError(f"Unknown SNMP MIB alias or invalid OID: {oid!r}")
        raw = f"{base}{suffix}"

    if not is_valid_oid(raw):
        raise ValidationError(f"Invalid SNMP OID: {oid!r}", details={"oid": oid})

    canonical = raw.lstrip(".")
    return f".{canonical}" if leading_dot else canonical


def oid_to_tuple(oid: str) -> tuple[int, ...]:
    """Parse an OID into a tuple of integer arcs for numeric sorting/comparison."""
    return tuple(int(part) for part in normalize_oid(oid).split("."))


def tuple_to_oid(arcs: Sequence[int], *, leading_dot: bool = False) -> str:
    """Convert a sequence of integer arcs back to a normalized OID string."""
    raw = ".".join(str(a) for a in arcs)
    return normalize_oid(raw, leading_dot=leading_dot)


def oid_is_child_of(child_oid: str, parent_oid: str, *, allow_equal: bool = True) -> bool:
    """Return True if ``child_oid`` falls within the subtree rooted at ``parent_oid``."""
    child = oid_to_tuple(child_oid)
    parent = oid_to_tuple(parent_oid)
    if len(child) < len(parent):
        return False
    if not allow_equal and len(child) == len(parent):
        return False
    return child[: len(parent)] == parent


def oid_common_prefix(oids: Sequence[str]) -> str | None:
    """Return the longest common ancestor OID shared by all given OIDs."""
    if not oids:
        return None
    tuples = [oid_to_tuple(o) for o in oids]
    min_len = min(len(t) for t in tuples)
    common: list[int] = []
    for idx in range(min_len):
        arc = tuples[0][idx]
        if all(t[idx] == arc for t in tuples[1:]):
            common.append(arc)
        else:
            break
    if len(common) < 2:
        return None
    return tuple_to_oid(common)


def oid_match_tree(oid: str, tree_map: Mapping[str, Any]) -> tuple[str, Any, tuple[int, ...]] | None:
    """Longest-prefix match ``oid`` against a mapping of base OIDs -> metadata.

    Returns ``(matched_base_oid, metadata, instance_suffix_arcs)`` or ``None``.
    """
    target = oid_to_tuple(oid)
    best_match: tuple[int, str, Any, tuple[int, ...]] | None = None
    for base_oid, value in tree_map.items():
        base_tuple = oid_to_tuple(base_oid)
        if len(target) >= len(base_tuple) and target[: len(base_tuple)] == base_tuple:
            if best_match is None or len(base_tuple) > best_match[0]:
                best_match = (len(base_tuple), normalize_oid(base_oid), value, target[len(base_tuple) :])
    if best_match is None:
        return None
    return best_match[1], best_match[2], best_match[3]


def resolve_oid_name(oid: str) -> str | None:
    """Resolve a numeric OID to its closest MIB symbol name (preserving instance index)."""
    matched = oid_match_tree(oid, _OID_TO_MIB_NAME)
    if matched is None:
        return None
    _, name, suffix = matched
    if suffix:
        return f"{name}." + ".".join(str(a) for a in suffix)
    return name


# ---------------------------------------------------------------------------
# Well-Known TCP/UDP Port Registry (110+ services)
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class PortInfo:
    port: int
    protocol: Literal["tcp", "udp", "both"]
    service: str
    category: str
    description: str
    encrypted: bool = False


_PORT_CATALOG: tuple[PortInfo, ...] = (
    PortInfo(7, "both", "echo", "diagnostic", "Echo Protocol"),
    PortInfo(20, "tcp", "ftp-data", "file_transfer", "FTP Data Transfer"),
    PortInfo(21, "tcp", "ftp", "file_transfer", "FTP Control"),
    PortInfo(22, "tcp", "ssh", "remote_access", "Secure Shell (SSH)", True),
    PortInfo(23, "tcp", "telnet", "remote_access", "Telnet (Unencrypted)"),
    PortInfo(25, "tcp", "smtp", "mail", "Simple Mail Transfer Protocol"),
    PortInfo(37, "both", "time", "infrastructure", "Time Protocol"),
    PortInfo(43, "tcp", "whois", "directory", "WHOIS Directory Service"),
    PortInfo(49, "both", "tacacs", "aaa", "TACACS+ Authentication"),
    PortInfo(53, "both", "dns", "infrastructure", "Domain Name System (DNS)"),
    PortInfo(67, "udp", "dhcp-server", "infrastructure", "DHCP Server / BOOTP"),
    PortInfo(68, "udp", "dhcp-client", "infrastructure", "DHCP Client / BOOTP"),
    PortInfo(69, "udp", "tftp", "file_transfer", "Trivial File Transfer Protocol"),
    PortInfo(80, "tcp", "http", "web", "Hypertext Transfer Protocol"),
    PortInfo(88, "both", "kerberos", "aaa", "Kerberos Authentication", True),
    PortInfo(110, "tcp", "pop3", "mail", "Post Office Protocol v3"),
    PortInfo(111, "both", "rpcbind", "infrastructure", "ONC RPC / Portmapper"),
    PortInfo(119, "tcp", "nntp", "messaging", "Network News Transfer Protocol"),
    PortInfo(123, "udp", "ntp", "infrastructure", "Network Time Protocol"),
    PortInfo(135, "tcp", "msrpc", "windows", "Microsoft EPMAP / RPC"),
    PortInfo(137, "udp", "netbios-ns", "windows", "NetBIOS Name Service"),
    PortInfo(138, "udp", "netbios-dgm", "windows", "NetBIOS Datagram Service"),
    PortInfo(139, "tcp", "netbios-ssn", "windows", "NetBIOS Session Service"),
    PortInfo(143, "tcp", "imap", "mail", "Internet Message Access Protocol"),
    PortInfo(161, "udp", "snmp", "monitoring", "Simple Network Management Protocol"),
    PortInfo(162, "udp", "snmptrap", "monitoring", "SNMP Trap Receiver"),
    PortInfo(179, "tcp", "bgp", "routing", "Border Gateway Protocol (BGP)"),
    PortInfo(194, "tcp", "irc", "messaging", "Internet Relay Chat"),
    PortInfo(389, "both", "ldap", "directory", "Lightweight Directory Access Protocol"),
    PortInfo(443, "tcp", "https", "web", "HTTP over TLS (HTTPS)", True),
    PortInfo(445, "tcp", "smb", "file_transfer", "Microsoft-DS / SMB"),
    PortInfo(464, "both", "kpasswd", "aaa", "Kerberos Password Change", True),
    PortInfo(465, "tcp", "smtps", "mail", "SMTP over Implicit TLS", True),
    PortInfo(500, "udp", "isakmp", "vpn", "IKE / IPsec Key Exchange", True),
    PortInfo(514, "udp", "syslog", "monitoring", "Syslog Log Ingestion"),
    PortInfo(515, "tcp", "lpd", "printing", "Line Printer Daemon"),
    PortInfo(520, "udp", "rip", "routing", "Routing Information Protocol"),
    PortInfo(521, "udp", "ripng", "routing", "RIP Next Generation (IPv6)"),
    PortInfo(546, "udp", "dhcpv6-client", "infrastructure", "DHCPv6 Client"),
    PortInfo(547, "udp", "dhcpv6-server", "infrastructure", "DHCPv6 Server"),
    PortInfo(554, "both", "rtsp", "media", "Real Time Streaming Protocol"),
    PortInfo(587, "tcp", "submission", "mail", "SMTP Mail Submission"),
    PortInfo(623, "udp", "ipmi", "management", "IPMI / RMCP Out-of-Band Management"),
    PortInfo(631, "both", "ipp", "printing", "Internet Printing Protocol / CUPS"),
    PortInfo(636, "tcp", "ldaps", "directory", "LDAP over TLS", True),
    PortInfo(646, "both", "ldp", "routing", "MPLS Label Distribution Protocol"),
    PortInfo(830, "tcp", "netconf-ssh", "management", "NETCONF over SSH", True),
    PortInfo(853, "tcp", "dns-over-tls", "infrastructure", "DNS over TLS (DoT)", True),
    PortInfo(873, "tcp", "rsync", "file_transfer", "Rsync File Synchronization"),
    PortInfo(902, "tcp", "vmware-authd", "virtualization", "VMware ESXi Management", True),
    PortInfo(989, "tcp", "ftps-data", "file_transfer", "FTP Data over TLS", True),
    PortInfo(990, "tcp", "ftps", "file_transfer", "FTP Control over TLS", True),
    PortInfo(993, "tcp", "imaps", "mail", "IMAP over TLS", True),
    PortInfo(995, "tcp", "pop3s", "mail", "POP3 over TLS", True),
    PortInfo(1080, "tcp", "socks", "proxy", "SOCKS Proxy"),
    PortInfo(1194, "both", "openvpn", "vpn", "OpenVPN Tunnel", True),
    PortInfo(1433, "tcp", "mssql", "database", "Microsoft SQL Server"),
    PortInfo(1521, "tcp", "oracle", "database", "Oracle Database Listener"),
    PortInfo(1701, "udp", "l2tp", "vpn", "Layer 2 Tunneling Protocol"),
    PortInfo(1723, "tcp", "pptp", "vpn", "Point-to-Point Tunneling Protocol"),
    PortInfo(1812, "udp", "radius", "aaa", "RADIUS Authentication"),
    PortInfo(1813, "udp", "radius-acct", "aaa", "RADIUS Accounting"),
    PortInfo(1883, "tcp", "mqtt", "messaging", "MQTT IoT Broker"),
    PortInfo(1985, "udp", "hsrp", "routing", "Cisco Hot Standby Router Protocol"),
    PortInfo(2049, "both", "nfs", "file_transfer", "Network File System (NFS)"),
    PortInfo(2055, "udp", "netflow", "monitoring", "Cisco NetFlow / IPFIX Collector"),
    PortInfo(2083, "tcp", "radsec", "aaa", "RADIUS over TLS (RadSec)", True),
    PortInfo(2181, "tcp", "zookeeper", "coordination", "Apache ZooKeeper"),
    PortInfo(2375, "tcp", "docker", "containers", "Docker Engine API (Plain)"),
    PortInfo(2376, "tcp", "docker-tls", "containers", "Docker Engine API (TLS)", True),
    PortInfo(2379, "tcp", "etcd-client", "coordination", "etcd Client API"),
    PortInfo(2380, "tcp", "etcd-peer", "coordination", "etcd Peer Communication"),
    PortInfo(3000, "tcp", "grafana", "monitoring", "Grafana / Web App UI"),
    PortInfo(3128, "tcp", "squid", "proxy", "HTTP Proxy (Squid)"),
    PortInfo(3268, "tcp", "msft-gc", "directory", "Active Directory Global Catalog"),
    PortInfo(3306, "tcp", "mysql", "database", "MySQL / MariaDB"),
    PortInfo(3389, "both", "rdp", "remote_access", "Remote Desktop Protocol", True),
    PortInfo(3784, "udp", "bfd-control", "routing", "Bidirectional Forwarding Detection"),
    PortInfo(3785, "udp", "bfd-echo", "routing", "BFD Echo"),
    PortInfo(4222, "tcp", "nats", "messaging", "NATS Messaging Client"),
    PortInfo(4369, "tcp", "epmd", "messaging", "Erlang Port Mapper Daemon"),
    PortInfo(4500, "udp", "ipsec-nat-t", "vpn", "IPsec NAT Traversal", True),
    PortInfo(4739, "both", "ipfix", "monitoring", "IP Flow Information Export (IPFIX)"),
    PortInfo(4789, "udp", "vxlan", "overlay", "Virtual Extensible LAN (VXLAN)"),
    PortInfo(5000, "tcp", "registry", "web", "Container Registry / Web API"),
    PortInfo(5044, "tcp", "logstash-beats", "monitoring", "Elastic Beats / Logstash"),
    PortInfo(5060, "both", "sip", "voip", "Session Initiation Protocol"),
    PortInfo(5061, "tcp", "sips", "voip", "SIP over TLS", True),
    PortInfo(5222, "tcp", "xmpp", "messaging", "XMPP Client"),
    PortInfo(5353, "udp", "mdns", "infrastructure", "Multicast DNS (mDNS)"),
    PortInfo(5432, "tcp", "postgresql", "database", "PostgreSQL Database"),
    PortInfo(5671, "tcp", "amqps", "messaging", "AMQP over TLS (RabbitMQ)", True),
    PortInfo(5672, "tcp", "amqp", "messaging", "AMQP Message Broker"),
    PortInfo(5900, "tcp", "vnc", "remote_access", "Virtual Network Computing (VNC)"),
    PortInfo(5985, "tcp", "winrm-http", "management", "Windows Remote Management (HTTP)"),
    PortInfo(5986, "tcp", "winrm-https", "management", "Windows Remote Management (HTTPS)", True),
    PortInfo(6081, "udp", "geneve", "overlay", "GENEVE Network Virtualization"),
    PortInfo(6343, "udp", "sflow", "monitoring", "sFlow Telemetry Collector"),
    PortInfo(6379, "tcp", "redis", "database", "Redis Key-Value Store"),
    PortInfo(6443, "tcp", "k8s-apiserver", "containers", "Kubernetes API Server", True),
    PortInfo(6514, "tcp", "syslog-tls", "monitoring", "Syslog over TLS", True),
    PortInfo(6653, "tcp", "openflow", "sdn", "OpenFlow SDN Controller"),
    PortInfo(7000, "tcp", "cassandra", "database", "Apache Cassandra Inter-node"),
    PortInfo(8000, "tcp", "http-alt", "web", "Alternate HTTP / API Server"),
    PortInfo(8080, "tcp", "http-proxy", "web", "HTTP Alternate / Proxy"),
    PortInfo(8086, "tcp", "influxdb", "monitoring", "InfluxDB Time-Series API"),
    PortInfo(8125, "udp", "statsd", "monitoring", "StatsD Metrics Receiver"),
    PortInfo(8291, "tcp", "winbox", "management", "MikroTik WinBox Management"),
    PortInfo(8443, "tcp", "https-alt", "web", "Alternate HTTPS", True),
    PortInfo(8500, "tcp", "consul", "coordination", "HashiCorp Consul HTTP API"),
    PortInfo(8883, "tcp", "mqtts", "messaging", "MQTT over TLS", True),
    PortInfo(9000, "tcp", "clickhouse-http", "database", "ClickHouse / SonarQube / MinIO"),
    PortInfo(9042, "tcp", "cassandra-cql", "database", "Apache Cassandra CQL"),
    PortInfo(9090, "tcp", "prometheus", "monitoring", "Prometheus Server"),
    PortInfo(9092, "tcp", "kafka", "messaging", "Apache Kafka Broker"),
    PortInfo(9093, "tcp", "alertmanager", "monitoring", "Prometheus Alertmanager"),
    PortInfo(9100, "tcp", "node-exporter", "monitoring", "Prometheus Node Exporter"),
    PortInfo(9200, "tcp", "elasticsearch", "monitoring", "Elasticsearch HTTP API"),
    PortInfo(9300, "tcp", "es-transport", "monitoring", "Elasticsearch Cluster Transport"),
    PortInfo(9995, "udp", "netflow-alt", "monitoring", "Alternate NetFlow Collector"),
    PortInfo(10050, "tcp", "zabbix-agent", "monitoring", "Zabbix Agent"),
    PortInfo(10051, "tcp", "zabbix-server", "monitoring", "Zabbix Server"),
    PortInfo(10250, "tcp", "kubelet", "containers", "Kubernetes Kubelet API", True),
    PortInfo(11211, "both", "memcached", "database", "Memcached Cache Server"),
    PortInfo(15672, "tcp", "rabbitmq-mgmt", "messaging", "RabbitMQ Management UI"),
    PortInfo(27017, "tcp", "mongodb", "database", "MongoDB Database"),
    PortInfo(51820, "udp", "wireguard", "vpn", "WireGuard VPN", True),
    PortInfo(57400, "tcp", "gnmi", "monitoring", "gRPC Network Management Interface (gNMI)", True),
)

WELL_KNOWN_PORTS: dict[int, PortInfo] = {info.port: info for info in _PORT_CATALOG}


def lookup_port(port: int, protocol: str = "tcp") -> PortInfo | None:
    """Look up service metadata for a TCP/UDP port number."""
    if not (0 <= port <= 65535):
        raise ValidationError(f"Port {port} out of valid range 0..65535")
    info = WELL_KNOWN_PORTS.get(port)
    if info is None:
        return None
    proto = protocol.lower()
    if info.protocol == "both" or info.protocol == proto:
        return info
    return None


def lookup_service_ports(service_query: str) -> list[PortInfo]:
    """Search the port registry by service name or category substring."""
    needle = service_query.strip().lower()
    if not needle:
        return []
    return [
        info
        for info in _PORT_CATALOG
        if needle in info.service.lower()
        or needle in info.category.lower()
        or needle in info.description.lower()
    ]


def is_ephemeral_port(port: int) -> bool:
    """Return True if ``port`` lies in the IANA dynamic/ephemeral range (49152..65535)."""
    return 49152 <= port <= 65535


def classify_port(port: int) -> str:
    """Classify a port as ``system`` (0-1023), ``registered`` (1024-49151), or ``ephemeral``."""
    if not (0 <= port <= 65535):
        raise ValidationError(f"Port {port} out of valid range 0..65535")
    if port <= 1023:
        return "system"
    if port <= 49151:
        return "registered"
    return "ephemeral"


# ---------------------------------------------------------------------------
# Bandwidth, Counter Math, Latency & Uptime Formatting Utilities
# ---------------------------------------------------------------------------

_BPS_UNITS: tuple[tuple[str, float], ...] = (
    ("Tbps", 1e12),
    ("Gbps", 1e9),
    ("Mbps", 1e6),
    ("Kbps", 1e3),
    ("bps", 1.0),
)

_BPS_PARSE_REGEX = re.compile(
    r"^\s*([0-9]+(?:\.[0-9]+)?)\s*(t|g|m|k)?\s*(?:b(?:its?)?(?:/s|ps)?)?\s*$",
    re.IGNORECASE,
)


def format_bps(bps: float, *, precision: int = 2) -> str:
    """Format bits-per-second into human-readable ``bps`` / ``Kbps`` / ``Mbps`` / ``Gbps`` / ``Tbps``."""
    sign = "-" if bps < 0 else ""
    val = abs(float(bps))
    for unit, scale in _BPS_UNITS:
        if val >= scale or unit == "bps":
            scaled = val / scale
            if unit == "bps":
                return f"{sign}{int(round(scaled))} bps"
            return f"{sign}{scaled:.{precision}f} {unit}"
    return f"{sign}0 bps"


def parse_bps(text: str) -> float:
    """Parse bandwidth strings like ``10 Gbps``, ``100Mbps``, or ``512 kbps`` into bps."""
    match = _BPS_PARSE_REGEX.match(text)
    if not match:
        raise ValidationError(f"Cannot parse bandwidth string: {text!r}")
    magnitude = float(match.group(1))
    prefix = (match.group(2) or "").lower()
    multipliers = {"": 1.0, "k": 1e3, "m": 1e6, "g": 1e9, "t": 1e12}
    return magnitude * multipliers[prefix]


def format_bytes(num_bytes: float, *, binary: bool = True, precision: int = 2) -> str:
    """Format a byte count using IEC binary (KiB/MiB/GiB) or SI decimal (KB/MB/GB) units."""
    sign = "-" if num_bytes < 0 else ""
    val = abs(float(num_bytes))
    base = 1024.0 if binary else 1000.0
    units = ("B", "KiB", "MiB", "GiB", "TiB", "PiB") if binary else ("B", "KB", "MB", "GB", "TB", "PB")
    for unit in units:
        if val < base or unit == units[-1]:
            if unit == "B":
                return f"{sign}{int(round(val))} B"
            return f"{sign}{val:.{precision}f} {unit}"
        val /= base
    return f"{sign}0 B"


def format_pps(pps: float, *, precision: int = 2) -> str:
    """Format packets-per-second into ``pps``, ``Kpps``, or ``Mpps``."""
    val = abs(float(pps))
    sign = "-" if pps < 0 else ""
    if val >= 1e6:
        return f"{sign}{val / 1e6:.{precision}f} Mpps"
    if val >= 1e3:
        return f"{sign}{val / 1e3:.{precision}f} Kpps"
    return f"{sign}{val:.{precision}f} pps"


def format_latency_ms(latency_ms: float) -> str:
    """Format latency from milliseconds into ``us``, ``ms``, or ``s``."""
    if latency_ms < 0:
        return "0.00 ms"
    if latency_ms < 1.0:
        return f"{latency_ms * 1000.0:.0f} us"
    if latency_ms >= 1000.0:
        return f"{latency_ms / 1000.0:.2f} s"
    return f"{latency_ms:.2f} ms"


def format_uptime(seconds: float, *, compact: bool = True) -> str:
    """Format elapsed seconds into readable uptime (e.g. ``14d 6h 32m 18s``)."""
    total_sec = max(0, int(seconds))
    days, rem = divmod(total_sec, 86400)
    hours, rem = divmod(rem, 3600)
    minutes, secs = divmod(rem, 60)

    if compact:
        parts: list[str] = []
        if days:
            parts.append(f"{days}d")
        if hours or parts:
            parts.append(f"{hours}h")
        if minutes or parts:
            parts.append(f"{minutes}m")
        parts.append(f"{secs}s")
        return " ".join(parts)

    long_parts: list[str] = []
    if days:
        long_parts.append(f"{days} day{'s' if days != 1 else ''}")
    if hours:
        long_parts.append(f"{hours} hour{'s' if hours != 1 else ''}")
    if minutes:
        long_parts.append(f"{minutes} minute{'s' if minutes != 1 else ''}")
    if secs or not long_parts:
        long_parts.append(f"{secs} second{'s' if secs != 1 else ''}")
    return ", ".join(long_parts)


def format_snmp_timeticks(timeticks: int) -> str:
    """Convert SNMP TimeTicks (hundredths of a second) to human-readable uptime."""
    return format_uptime(max(0, timeticks) / 100.0)


def counter_delta(previous: int, current: int, *, bits: Literal[32, 64] = 64) -> int:
    """Compute monotonic SNMP counter delta handling 32-bit or 64-bit counter wraps."""
    if current >= previous:
        return current - previous
    modulus = 1 << bits
    return (modulus - previous) + current


def calculate_utilization_pct(
    octets_delta: int,
    interval_seconds: float,
    interface_speed_bps: float,
) -> float:
    """Calculate interface bandwidth utilization percentage (clamped 0.0..100.0)."""
    if interval_seconds <= 0 or interface_speed_bps <= 0 or octets_delta <= 0:
        return 0.0
    bps = (octets_delta * 8.0) / interval_seconds
    pct = (bps / interface_speed_bps) * 100.0
    return round(min(100.0, max(0.0, pct)), 3)


def calculate_jitter_ms(rtt_samples_ms: Sequence[float]) -> float:
    """Calculate RFC 3550-style mean absolute inter-packet latency variation (jitter)."""
    if len(rtt_samples_ms) < 2:
        return 0.0
    diffs = [abs(rtt_samples_ms[i] - rtt_samples_ms[i - 1]) for i in range(1, len(rtt_samples_ms))]
    return round(sum(diffs) / len(diffs), 3)


def calculate_packet_loss_pct(sent: int, received: int) -> float:
    """Calculate percentage of lost probe packets (0.0..100.0)."""
    if sent <= 0:
        return 0.0
    clamped_recv = max(0, min(sent, received))
    return round(((sent - clamped_recv) / sent) * 100.0, 2)
