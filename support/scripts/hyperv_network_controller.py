#!/usr/bin/env python3
# SPDX-License-Identifier: BSD-3-Clause

import base64
import hashlib
import importlib.util
import ipaddress
import json
from pathlib import Path
import re
import sys


RAW_ACCEPTANCE_MODE = "raw-dhcp"
NETWORK_ACCEPTANCE_MODE = "network-application"
PEER_VM_SIZE = "Standard_B1s"
PEER_TIMEOUT_SECONDS = 600
OPERATION_TIMEOUT_SECONDS = 5
PEER_IMAGE = {
    "publisher": "Canonical",
    "offer": "ubuntu-24_04-lts",
    "sku": "server",
}
TCP_CASES = ((1, 31), (2, 1400), (3, 257))
TCP_MIN_WRITES = (2, 9, 3)
TCP_MIN_WRITE_TOTAL = sum(TCP_MIN_WRITES)
UDP_CASES = (
    (0x100, 19), (0x101, 1448), (0x102, 73),
    (0x103, 1448), (0x104, 257), (0x105, 19),
)
TCP_BYTES = sum(24 + length for _, length in TCP_CASES)
UDP_BYTES = sum(24 + length for _, length in UDP_CASES)
PEER_SCRIPT = Path(__file__).with_name("hyperv-network-peer.py")
BOOTSTRAP_PREFIX = "HYPERV_NETWORK_BOOTSTRAP "
PEER_PREFIX = "HYPERV_NETWORK_PEER "
SHA256 = re.compile(r"[0-9a-f]{64}")
NONCE = re.compile(r"[0-9a-f]{16}")
MAC = re.compile(r"(?:[0-9a-f]{2}:){5}[0-9a-f]{2}")
ANSI_ESCAPE = re.compile(r"\x1b\[[0-?]*[ -/]*[@-~]")
MAIN_RETURN = re.compile(
    r"^(?:\[\s*[0-9]+(?:\.[0-9]+)?\]\s+)?"
    r"(?:Info:\s+)?(?:\[[A-Za-z0-9_.-]{1,64}\]\s+)?"
    r"(?:<[^<>\r\n]{1,160}>:?\s+)?main returned (-?[0-9]+)$"
)


class EvidenceIncomplete(RuntimeError):
    pass


def _exact_fields(value, fields, description):
    if not isinstance(value, dict) or set(value) != set(fields):
        raise ValueError(f"{description} has unknown or missing fields")
    return value


def _sha256(value, description):
    if not isinstance(value, str) or not SHA256.fullmatch(value):
        raise ValueError(f"{description} is not a lowercase SHA-256 digest")
    return value


def _private_ipv4(value, description):
    if not isinstance(value, str):
        raise ValueError(f"{description} is not an IPv4 address")
    try:
        address = ipaddress.IPv4Address(value)
    except ipaddress.AddressValueError as error:
        raise ValueError(f"{description} is not an IPv4 address") from error
    private_ranges = (
        ipaddress.IPv4Network("10.0.0.0/8"),
        ipaddress.IPv4Network("172.16.0.0/12"),
        ipaddress.IPv4Network("192.168.0.0/16"),
    )
    if not any(address in network for network in private_ranges):
        raise ValueError(f"{description} must be an RFC 1918 address")
    return address


def _port(value, description):
    if type(value) is not int or not 1 <= value <= 65535:
        raise ValueError(f"{description} must be an integer TCP/UDP port")
    return value


def _wire_integer(value, description, minimum=0):
    if type(value) is not int or value < minimum:
        raise ValueError(f"{description} is not an integer at least {minimum}")
    return value


def _require_wire_integers(value, fields, description):
    for field in fields:
        _wire_integer(value[field], f"{description} {field}")


def _load_peer():
    specification = importlib.util.spec_from_file_location(
        "hyperv_network_peer_contract", PEER_SCRIPT
    )
    if specification is None or specification.loader is None:
        raise RuntimeError("Unable to load the pinned Hyper-V network peer")
    module = importlib.util.module_from_spec(specification)
    sys.modules[specification.name] = module
    try:
        specification.loader.exec_module(module)
    finally:
        sys.modules.pop(specification.name, None)
    return module


def transcript_contract(nonce):
    if not isinstance(nonce, str) or not NONCE.fullmatch(nonce):
        raise ValueError("Application-network nonce must be 16 lowercase hex digits")
    peer = _load_peer()
    nonce_value = int(nonce, 16)

    def transcript(direction):
        return b"".join(
            peer.message(transport, direction, sequence, length, nonce_value)
            for transport, cases in ((1, TCP_CASES), (2, UDP_CASES))
            for sequence, length in cases
        )

    requests = transcript(1)
    responses = transcript(2)
    if len(requests) != TCP_BYTES + UDP_BYTES or len(responses) != len(requests):
        raise RuntimeError("Pinned peer protocol totals changed unexpectedly")
    return {
        "schema": "ukna-v1",
        "request_sha256": hashlib.sha256(requests).hexdigest(),
        "response_sha256": hashlib.sha256(responses).hexdigest(),
        "tcp_connections": len(TCP_CASES),
        "udp_datagrams": len(UDP_CASES),
        "tcp_bytes": TCP_BYTES,
        "udp_bytes": UDP_BYTES,
    }


def validate_acceptance(value):
    if not isinstance(value, dict) or value.get("mode") not in (
        RAW_ACCEPTANCE_MODE, NETWORK_ACCEPTANCE_MODE,
    ):
        raise ValueError("Prepared image has an unsupported acceptance mode")
    if value["mode"] == RAW_ACCEPTANCE_MODE:
        return dict(_exact_fields(value, ("mode",), "Raw acceptance contract"))

    value = _exact_fields(value, (
        "mode", "peer_ipv4", "tcp_port", "udp_port", "nonce",
        "solved_config_sha256", "peer_script_sha256", "transcript",
    ), "Application-network acceptance contract")
    peer_ipv4 = str(_private_ipv4(value["peer_ipv4"], "Peer IPv4"))
    tcp_port = _port(value["tcp_port"], "Peer TCP port")
    udp_port = _port(value["udp_port"], "Peer UDP port")
    if tcp_port == udp_port:
        raise ValueError("Peer TCP and UDP ports must be distinct")
    nonce = value["nonce"]
    if not isinstance(nonce, str) or not NONCE.fullmatch(nonce):
        raise ValueError("Application-network nonce must be 16 lowercase hex digits")
    solved_config_sha256 = _sha256(
        value["solved_config_sha256"], "Solved configuration fingerprint"
    )
    peer_script_sha256 = _sha256(
        value["peer_script_sha256"], "Peer script fingerprint"
    )
    transcript = _exact_fields(value["transcript"], (
        "schema", "request_sha256", "response_sha256", "tcp_connections",
        "udp_datagrams", "tcp_bytes", "udp_bytes",
    ), "Application-network transcript contract")
    expected_transcript = transcript_contract(nonce)
    if transcript != expected_transcript:
        raise ValueError("Application-network transcript contract is incompatible")
    return {
        "mode": NETWORK_ACCEPTANCE_MODE,
        "peer_ipv4": peer_ipv4,
        "tcp_port": tcp_port,
        "udp_port": udp_port,
        "nonce": nonce,
        "solved_config_sha256": solved_config_sha256,
        "peer_script_sha256": peer_script_sha256,
        "transcript": expected_transcript,
    }


def acceptance_from_solved_config(config_bytes, peer_script_bytes):
    if not isinstance(config_bytes, bytes) or not isinstance(peer_script_bytes, bytes):
        raise TypeError("Solved configuration and peer script must be bytes")
    try:
        lines = config_bytes.decode("utf-8").splitlines()
    except UnicodeDecodeError as error:
        raise ValueError("Solved application-network configuration is not UTF-8") from error

    values = {}
    wanted = {
        "CONFIG_APPHYPERVACCEPTANCE_NETWORK_APPLICATION",
        "CONFIG_APPHYPERVACCEPTANCE_PEER_IPV4",
        "CONFIG_APPHYPERVACCEPTANCE_PEER_TCP_PORT",
        "CONFIG_APPHYPERVACCEPTANCE_PEER_UDP_PORT",
        "CONFIG_APPHYPERVACCEPTANCE_NONCE",
    }
    for line in lines:
        if "=" not in line:
            continue
        key, raw = line.split("=", 1)
        if key not in wanted:
            continue
        if key in values:
            raise ValueError(f"Solved configuration repeats {key}")
        values[key] = raw
    if set(values) != wanted:
        raise ValueError("Solved configuration is missing application-network fields")
    if values["CONFIG_APPHYPERVACCEPTANCE_NETWORK_APPLICATION"] != "y":
        raise ValueError("Solved configuration does not enable application networking")

    def quoted(name):
        value = values[name]
        if not re.fullmatch(r'"[^"\r\n]*"', value):
            raise ValueError(f"Solved configuration has an invalid {name}")
        return value[1:-1]

    try:
        tcp_port = int(values["CONFIG_APPHYPERVACCEPTANCE_PEER_TCP_PORT"], 10)
        udp_port = int(values["CONFIG_APPHYPERVACCEPTANCE_PEER_UDP_PORT"], 10)
    except ValueError as error:
        raise ValueError("Solved configuration has a malformed peer port") from error
    acceptance = {
        "mode": NETWORK_ACCEPTANCE_MODE,
        "peer_ipv4": quoted("CONFIG_APPHYPERVACCEPTANCE_PEER_IPV4"),
        "tcp_port": tcp_port,
        "udp_port": udp_port,
        "nonce": quoted("CONFIG_APPHYPERVACCEPTANCE_NONCE").lower(),
        "solved_config_sha256": hashlib.sha256(config_bytes).hexdigest(),
        "peer_script_sha256": hashlib.sha256(peer_script_bytes).hexdigest(),
        "transcript": transcript_contract(
            quoted("CONFIG_APPHYPERVACCEPTANCE_NONCE").lower()
        ),
    }
    return validate_acceptance(acceptance)


def configuration_marker(acceptance):
    acceptance = validate_acceptance(acceptance)
    if acceptance["mode"] != NETWORK_ACCEPTANCE_MODE:
        raise ValueError("A network acceptance contract is required")
    return (
        "HYPERV_ACCEPTANCE NETWORK_APP_CONFIG PASS "
        f"peer_ipv4={acceptance['peer_ipv4']} "
        f"tcp_port={acceptance['tcp_port']} udp_port={acceptance['udp_port']} "
        f"nonce={acceptance['nonce']} "
        f"tcp_connections={len(TCP_CASES)} udp_datagrams={len(UDP_CASES)}"
    )


def validate_preflight_log(text, acceptance):
    marker = configuration_marker(acceptance)
    lines = _lines(text)
    if lines.count(marker) != 1:
        raise ValueError("Local preflight log lacks one exact network CONFIG record")
    if any(
        line.startswith("HYPERV_ACCEPTANCE NETWORK_APP_FINAL PASS")
        or line == "UK_HYPERV_NETWORK_APP_READY"
        or line == "UK_HYPERV_IO_READY"
        for line in lines
    ):
        raise ValueError("Local preflight log incorrectly claims live network I/O")


def private_network(acceptance, guest_ipv4, subnet):
    acceptance = validate_acceptance(acceptance)
    if acceptance["mode"] != NETWORK_ACCEPTANCE_MODE:
        raise ValueError("A network acceptance contract is required")
    try:
        network = ipaddress.IPv4Network(subnet, strict=True)
    except (ipaddress.AddressValueError, ipaddress.NetmaskValueError) as error:
        raise ValueError("Private subnet must be a canonical IPv4 network") from error
    if network.prefixlen != 29 or not network.is_private:
        raise ValueError("Application-network subnet must be a private /29")
    peer = _private_ipv4(acceptance["peer_ipv4"], "Peer IPv4")
    guest = _private_ipv4(guest_ipv4, "Guest IPv4")
    if peer not in network or guest not in network or peer == guest:
        raise ValueError("Peer and guest must be distinct addresses in the private subnet")
    addresses = list(network)
    if peer in addresses[:4] or guest in addresses[:4] or peer == addresses[-1] or guest == addresses[-1]:
        raise ValueError("Peer and guest addresses must avoid Azure-reserved subnet addresses")
    return {
        "subnet": str(network),
        "netmask": str(network.netmask),
        "gateway": str(addresses[1]),
        "peer_ipv4": str(peer),
        "guest_ipv4": str(guest),
        "tcp_port": acceptance["tcp_port"],
        "udp_port": acceptance["udp_port"],
        "nonce": acceptance["nonce"],
    }


def peer_bootstrap(peer_script_bytes, acceptance, network):
    acceptance = validate_acceptance(acceptance)
    network = private_network(
        acceptance, network["guest_ipv4"], network["subnet"]
    )
    if hashlib.sha256(peer_script_bytes).hexdigest() != acceptance["peer_script_sha256"]:
        raise ValueError("Pinned peer script does not match the prepared image contract")
    script_sha256 = acceptance["peer_script_sha256"]
    runner = f"""#!/usr/bin/python3
import json
import subprocess
import sys

def emit(event, **fields):
    print({BOOTSTRAP_PREFIX!r} + json.dumps({{"schema": 1, "event": event, **fields}},
          sort_keys=True), flush=True)

emit("START", peer_script_sha256={script_sha256!r},
     timeout_seconds={PEER_TIMEOUT_SECONDS})
completed = subprocess.run(sys.argv[1:], check=False)
emit("EOF", exit_code=completed.returncode)
raise SystemExit(completed.returncode)
"""
    command = (
        "/usr/bin/python3 /opt/unikraft/hyperv-network-peer.py "
        f"--peer-ip {network['peer_ipv4']} --guest-ip {network['guest_ipv4']} "
        f"--tcp-port {network['tcp_port']} --udp-port {network['udp_port']} "
        f"--nonce {network['nonce']} --timeout {PEER_TIMEOUT_SECONDS}"
    )
    unit = f"""[Unit]
Description=Bounded Unikraft Hyper-V private network peer
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=nobody
Group=nogroup
Environment=PYTHONDONTWRITEBYTECODE=1
ExecStart=/usr/bin/python3 /opt/unikraft/hyperv-network-peer-runner.py {command}
Restart=no
RuntimeMaxSec={PEER_TIMEOUT_SECONDS}
TimeoutStopSec={OPERATION_TIMEOUT_SECONDS}
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ProtectHome=true
RestrictAddressFamilies=AF_INET
RestrictNamespaces=true
CapabilityBoundingSet=
StandardOutput=append:/dev/ttyS0
StandardError=append:/dev/ttyS0

[Install]
WantedBy=multi-user.target
"""
    encoded_peer = base64.b64encode(peer_script_bytes).decode("ascii")
    encoded_runner = base64.b64encode(runner.encode()).decode("ascii")
    encoded_unit = base64.b64encode(unit.encode()).decode("ascii")
    return f"""#cloud-config
write_files:
  - path: /opt/unikraft/hyperv-network-peer.py
    owner: root:root
    permissions: '0555'
    encoding: b64
    content: {encoded_peer}
  - path: /opt/unikraft/hyperv-network-peer-runner.py
    owner: root:root
    permissions: '0555'
    encoding: b64
    content: {encoded_runner}
  - path: /etc/systemd/system/unikraft-hyperv-network-peer.service
    owner: root:root
    permissions: '0444'
    encoding: b64
    content: {encoded_unit}
runcmd:
  - [systemctl, daemon-reload]
  - [systemctl, enable, --now, unikraft-hyperv-network-peer.service]
"""


def _lines(text):
    if not isinstance(text, str):
        raise ValueError("Serial evidence must be text")
    return [
        ANSI_ESCAPE.sub("", line).replace("\0", "").strip()
        for line in text.splitlines()
    ]


def _strict_json(text, description):
    def unique(pairs):
        value = {}
        for key, item in pairs:
            if key in value:
                raise ValueError(f"{description} repeats field {key!r}")
            value[key] = item
        return value

    try:
        return json.loads(text, object_pairs_hook=unique)
    except (json.JSONDecodeError, RecursionError) as error:
        raise ValueError(f"{description} is malformed JSON") from error


def _single_record(lines, prefix, fields, description, *, required=True):
    records = [line for line in lines if line.startswith(prefix)]
    failures = [line for line in records if not line.startswith(prefix + "PASS ")]
    if failures:
        raise ValueError(f"{description} reported failure")
    if not records:
        if required:
            raise EvidenceIncomplete(f"{description} has not appeared")
        return None, None
    if len(records) != 1:
        raise ValueError(f"{description} is duplicated")
    tokens = records[0][len(prefix):].split()
    if not tokens or tokens[0] != "PASS":
        raise ValueError(f"{description} is malformed")
    values = {}
    for token in tokens[1:]:
        if "=" not in token:
            raise ValueError(f"{description} has a malformed field")
        key, value = token.split("=", 1)
        if key in values:
            raise ValueError(f"{description} repeats field {key}")
        values[key] = value
    if set(values) != set(fields):
        raise ValueError(f"{description} has unknown or missing fields")
    return lines.index(records[0]), values


def _integer(value, description, minimum=0):
    if not re.fullmatch(r"[0-9]+", value):
        raise ValueError(f"{description} is not a decimal integer")
    result = int(value)
    if result < minimum:
        raise ValueError(f"{description} is below its required minimum")
    return result


def inspect_guest_log(text, acceptance, network):
    acceptance = validate_acceptance(acceptance)
    network = private_network(
        acceptance, network["guest_ipv4"], network["subnet"]
    )
    lines = _lines(text)
    if any(
        "Unikraft Crash" in line
        or "Assertion failure" in line
        or "Exception Type" in line
        or line.startswith("UK_HYPERV_ACCEPTANCE_FAIL:")
        or line.startswith("UK_HYPERV_ACCEPTANCE_UNAVAILABLE:")
        or line.startswith("HYPERV_ACCEPTANCE NETWORK_APP_") and " FAIL " in line
        for line in lines
    ):
        raise ValueError("Guest serial stream contains an acceptance failure")
    if any(
        "HYPERV_ACCEPTANCE NETWORK_DHCP PASS" in line
        or line == "UK_HYPERV_NET_DHCP_OFFER"
        for line in lines
    ):
        raise ValueError("Raw DHCP evidence is invalid for application-network acceptance")

    records = []
    index, config = _single_record(
        lines, "HYPERV_ACCEPTANCE NETWORK_APP_CONFIG ",
        ("peer_ipv4", "tcp_port", "udp_port", "nonce",
         "tcp_connections", "udp_datagrams"),
        "Guest CONFIG record",
    )
    records.append(index)
    expected_config = {
        "peer_ipv4": acceptance["peer_ipv4"],
        "tcp_port": str(acceptance["tcp_port"]),
        "udp_port": str(acceptance["udp_port"]),
        "nonce": acceptance["nonce"],
        "tcp_connections": str(len(TCP_CASES)),
        "udp_datagrams": str(len(UDP_CASES)),
    }
    if config != expected_config:
        raise ValueError("Guest CONFIG record does not match the prepared image")

    index, lease = _single_record(
        lines, "HYPERV_ACCEPTANCE NETWORK_APP_LEASE ",
        ("address", "netmask", "gateway", "mtu", "server", "xid", "state",
         "retries", "lease_seconds", "proof"),
        "Guest LEASE record",
    )
    records.append(index)
    if (
        lease["address"] != network["guest_ipv4"]
        or lease["netmask"] != network["netmask"]
        or lease["gateway"] != network["gateway"]
        or lease["proof"] != "discover-offer-request-ack-bound"
        or not re.fullmatch(r"[0-9a-f]{8}", lease["xid"])
        or _integer(lease["mtu"], "Guest MTU", 576) > 65535
        or _integer(lease["state"], "Guest DHCP state") <= 0
        or _integer(lease["lease_seconds"], "Guest DHCP lease", 1) <= 0
    ):
        raise ValueError("Guest lease does not match the reserved private NIC")
    _integer(lease["retries"], "Guest DHCP retries")
    if lease["server"] != "168.63.129.16":
        raise ValueError("Guest DHCP server is not the Azure platform wire server")

    index, arp = _single_record(
        lines, "HYPERV_ACCEPTANCE NETWORK_APP_ARP ",
        ("peer", "mac", "requests"), "Guest ARP record",
    )
    records.append(index)
    requests = _integer(arp["requests"], "Guest ARP requests", 1)
    if (
        arp["peer"] != network["peer_ipv4"]
        or not MAC.fullmatch(arp["mac"].lower())
        or requests > 64
    ):
        raise ValueError("Guest ARP record does not match the private peer")

    index, tcp = _single_record(
        lines, "HYPERV_ACCEPTANCE NETWORK_APP_TCP ",
        ("connections", "tx_messages", "rx_messages", "tx_bytes", "rx_bytes",
         "write_chunks", "rx_callbacks", "rx_pbuf_freed", "close_accepted"),
        "Guest TCP record",
    )
    records.append(index)
    tcp_values = {key: _integer(value, f"Guest TCP {key}") for key, value in tcp.items()}
    if (
        tcp_values["connections"] != len(TCP_CASES)
        or tcp_values["tx_messages"] != len(TCP_CASES)
        or tcp_values["rx_messages"] != len(TCP_CASES)
        or tcp_values["tx_bytes"] != TCP_BYTES
        or tcp_values["rx_bytes"] != TCP_BYTES
        or tcp_values["close_accepted"] != len(TCP_CASES)
        or tcp_values["write_chunks"] < TCP_MIN_WRITE_TOTAL
        or tcp_values["rx_callbacks"] < len(TCP_CASES)
        or tcp_values["rx_pbuf_freed"] != tcp_values["rx_callbacks"]
    ):
        raise ValueError("Guest TCP counts or cleanup are invalid")

    index, udp = _single_record(
        lines, "HYPERV_ACCEPTANCE NETWORK_APP_UDP ",
        ("datagrams", "tx_bytes", "rx_bytes", "pbuf_allocated", "pbuf_freed",
         "rx_pbuf_freed", "pcb_removed", "unrelated"),
        "Guest UDP record",
    )
    records.append(index)
    udp_values = {key: _integer(value, f"Guest UDP {key}") for key, value in udp.items()}
    if (
        udp_values["datagrams"] != len(UDP_CASES)
        or udp_values["tx_bytes"] != UDP_BYTES
        or udp_values["rx_bytes"] != UDP_BYTES
        or udp_values["pbuf_allocated"] != len(UDP_CASES)
        or udp_values["pbuf_freed"] != len(UDP_CASES)
        or udp_values["rx_pbuf_freed"] != len(UDP_CASES)
        or udp_values["pcb_removed"] != 1
        or udp_values["unrelated"] != 0
    ):
        raise ValueError("Guest UDP counts or cleanup are invalid")

    index, final = _single_record(
        lines, "HYPERV_ACCEPTANCE NETWORK_APP_FINAL ",
        ("lease", "arp", "tcp", "udp", "tcp_connections", "udp_datagrams",
         "peer_ipv4", "tcp_port", "udp_port", "nonce", "adapter_rx_packets",
         "adapter_rx_budget_exhaustions", "adapter_tx_attempts",
         "adapter_tx_busy"),
        "Guest FINAL record",
    )
    records.append(index)
    if (
        any(final[key] != "PASS" for key in ("lease", "arp", "tcp", "udp"))
        or final["peer_ipv4"] != acceptance["peer_ipv4"]
        or final["tcp_port"] != str(acceptance["tcp_port"])
        or final["udp_port"] != str(acceptance["udp_port"])
        or final["nonce"] != acceptance["nonce"]
        or _integer(final["tcp_connections"], "Guest final TCP count")
        != len(TCP_CASES)
        or _integer(final["udp_datagrams"], "Guest final UDP count")
        != len(UDP_CASES)
        or _integer(final["adapter_rx_packets"], "Guest adapter RX packets", 1) <= 0
        or _integer(
            final["adapter_tx_attempts"], "Guest adapter TX attempts", 1
        ) <= 0
        or _integer(final["adapter_tx_busy"], "Guest adapter TX busy") != 0
    ):
        raise ValueError("Guest FINAL record is not an error-free correlated pass")
    _integer(
        final["adapter_rx_budget_exhaustions"],
        "Guest adapter RX budget exhaustions",
    )

    unique_markers = (
        "UK_HYPERV_PLATFORM_READY", "UK_HYPERV_BLOCK_READ_OK",
        "UK_HYPERV_NET_APP_LEASE", "UK_HYPERV_NET_APP_ARP",
        "UK_HYPERV_NET_APP_TCP", "UK_HYPERV_NET_APP_UDP",
        "UK_HYPERV_NETWORK_APP_READY", "UK_HYPERV_IO_READY",
        "HYPERV_ACCEPTANCE FINAL_RESULT PASS storage=PASS network=PASS",
    )
    marker_positions = []
    for marker in unique_markers:
        if lines.count(marker) == 0:
            raise EvidenceIncomplete(f"Guest marker {marker} has not appeared")
        if lines.count(marker) != 1:
            raise ValueError(f"Guest marker {marker} is duplicated")
        marker_positions.append(lines.index(marker))
    main_records = [
        (index, line, MAIN_RETURN.fullmatch(line))
        for index, line in enumerate(lines)
        if "main returned" in line
    ]
    if not main_records:
        raise EvidenceIncomplete("Guest main return has not appeared")
    if (
        len(main_records) != 1
        or main_records[0][2] is None
        or int(main_records[0][2].group(1)) != 0
    ):
        raise ValueError("Guest main return is malformed, nonzero, or duplicated")
    main_position = main_records[0][0]
    expected_order = (
        marker_positions[0], marker_positions[1],
        records[0], records[1], marker_positions[2],
        records[2], marker_positions[3],
        records[3], marker_positions[4],
        records[4], marker_positions[5],
        records[5], marker_positions[6],
        marker_positions[7], marker_positions[8], main_position,
    )
    if list(expected_order) != sorted(expected_order) or len(set(expected_order)) != len(expected_order):
        raise ValueError("Guest application-network evidence is stale, duplicated, or out of order")
    return {
        "lease": {
            "address": lease["address"], "netmask": lease["netmask"],
            "gateway": lease["gateway"], "server": lease["server"],
            "xid": lease["xid"], "lease_seconds": int(lease["lease_seconds"]),
        },
        "arp": {"peer": arp["peer"], "mac": arp["mac"].lower(), "requests": requests},
        "tcp": tcp_values,
        "udp": udp_values,
        "final": {
            "adapter_rx_packets": int(final["adapter_rx_packets"]),
            "adapter_rx_budget_exhaustions": int(
                final["adapter_rx_budget_exhaustions"]
            ),
            "adapter_tx_attempts": int(final["adapter_tx_attempts"]),
            "adapter_tx_busy": int(final["adapter_tx_busy"]),
        },
    }


def _json_records(lines, prefix, description):
    records = []
    for index, line in enumerate(lines):
        if line.startswith(prefix):
            value = _strict_json(line[len(prefix):], description)
            if not isinstance(value, dict):
                raise ValueError(f"{description} is not a JSON object")
            records.append((index, value))
    return records


def inspect_peer_ready(text, acceptance, network):
    acceptance = validate_acceptance(acceptance)
    network = private_network(
        acceptance, network["guest_ipv4"], network["subnet"]
    )
    lines = _lines(text)
    bootstrap = _json_records(lines, BOOTSTRAP_PREFIX, "Peer bootstrap record")
    peer = _json_records(lines, PEER_PREFIX, "Peer protocol record")
    starts = [(index, value) for index, value in bootstrap if value.get("event") == "START"]
    ready = [(index, value) for index, value in peer if value.get("event") == "READY"]
    if len(starts) > 1 or len(ready) > 1:
        raise ValueError("Peer process restarted before guest creation")
    if (
        any(value.get("event") != "START" for _, value in bootstrap)
        or any(value.get("event") != "READY" for _, value in peer)
    ):
        raise ValueError("Peer emitted unexpected lifecycle data before guest creation")
    if any(value.get("result") == "FAIL" for _, value in peer):
        raise ValueError("Peer failed before guest creation")
    if not starts or not ready:
        raise EvidenceIncomplete("Peer READY has not appeared")
    start_index, start_value = starts[0]
    ready_index, ready_value = ready[0]
    start = _exact_fields(
        start_value,
        ("schema", "event", "peer_script_sha256", "timeout_seconds"),
        "Peer START record",
    )
    _require_wire_integers(
        start, ("schema", "timeout_seconds"), "Peer START record"
    )
    if start != {
        "schema": 1, "event": "START",
        "peer_script_sha256": acceptance["peer_script_sha256"],
        "timeout_seconds": PEER_TIMEOUT_SECONDS,
    }:
        raise ValueError("Peer START record does not match the prepared controller")
    ready_value = _exact_fields(
        ready_value,
        ("schema", "event", "peer_ip", "guest_ip", "tcp_port", "udp_port", "nonce"),
        "Peer READY record",
    )
    _require_wire_integers(
        ready_value, ("schema", "tcp_port", "udp_port"), "Peer READY record"
    )
    expected = {
        "schema": 1, "event": "READY", "peer_ip": network["peer_ipv4"],
        "guest_ip": network["guest_ipv4"], "tcp_port": network["tcp_port"],
        "udp_port": network["udp_port"], "nonce": network["nonce"],
    }
    if ready_value != expected:
        raise ValueError("Peer READY does not match the exact guest configuration")
    if start_index >= ready_index:
        raise ValueError("Peer READY preceded its process START record")
    return {key: value for key, value in expected.items() if key not in ("schema", "event")}


def inspect_peer_log(text, acceptance, network):
    acceptance = validate_acceptance(acceptance)
    network = private_network(
        acceptance, network["guest_ipv4"], network["subnet"]
    )
    lines = _lines(text)
    bootstrap = _json_records(lines, BOOTSTRAP_PREFIX, "Peer bootstrap record")
    peer = _json_records(lines, PEER_PREFIX, "Peer protocol record")
    starts = [(index, value) for index, value in bootstrap if value.get("event") == "START"]
    eof = [(index, value) for index, value in bootstrap if value.get("event") == "EOF"]
    if any(value.get("event") not in ("START", "EOF") for _, value in bootstrap):
        raise ValueError("Peer bootstrap emitted an unknown lifecycle event")
    if len(starts) > 1 or len(eof) > 1:
        raise ValueError("Peer process restarted or emitted duplicate lifecycle records")
    if not starts:
        raise EvidenceIncomplete("Peer process has not started")
    start_index, start = starts[0]
    _exact_fields(
        start, ("schema", "event", "peer_script_sha256", "timeout_seconds"),
        "Peer START record",
    )
    _require_wire_integers(
        start, ("schema", "timeout_seconds"), "Peer START record"
    )
    if (
        start["schema"] != 1
        or start["peer_script_sha256"] != acceptance["peer_script_sha256"]
        or start["timeout_seconds"] != PEER_TIMEOUT_SECONDS
    ):
        raise ValueError("Peer START record does not match the prepared controller")

    allowed = {"READY", "TCP", "UDP", "FINAL"}
    if any(value.get("event") not in allowed for _, value in peer):
        raise ValueError("Peer emitted an unknown protocol event")
    if any(value.get("result") == "FAIL" for _, value in peer):
        raise ValueError("Peer protocol stream reported failure")
    ready = [(index, value) for index, value in peer if value.get("event") == "READY"]
    tcp = [(index, value) for index, value in peer if value.get("event") == "TCP"]
    udp = [(index, value) for index, value in peer if value.get("event") == "UDP"]
    final = [(index, value) for index, value in peer if value.get("event") == "FINAL"]
    if len(ready) > 1 or len(final) > 1:
        raise ValueError("Peer process restarted or emitted duplicate final records")
    if not ready:
        raise EvidenceIncomplete("Peer READY has not appeared")

    endpoint_fields = {
        "schema": 1, "peer_ip": network["peer_ipv4"],
        "guest_ip": network["guest_ipv4"], "tcp_port": network["tcp_port"],
        "udp_port": network["udp_port"], "nonce": network["nonce"],
    }
    ready_index, ready_value = ready[0]
    _exact_fields(
        ready_value,
        ("schema", "event", "peer_ip", "guest_ip", "tcp_port", "udp_port", "nonce"),
        "Peer READY record",
    )
    _require_wire_integers(
        ready_value, ("schema", "tcp_port", "udp_port"), "Peer READY record"
    )
    if ready_value != {"event": "READY", **endpoint_fields}:
        raise ValueError("Peer READY does not match the exact guest configuration")

    if len(tcp) > len(TCP_CASES) or len(udp) > len(UDP_CASES):
        raise ValueError("Peer emitted duplicate exchange records")
    tcp_writes = []
    for (index, value), (sequence, body_length), minimum_writes in zip(
        tcp, TCP_CASES, TCP_MIN_WRITES
    ):
        _exact_fields(
            value,
            ("schema", "event", "result", "sequence", "rx_bytes", "tx_bytes", "writes"),
            "Peer TCP record",
        )
        _require_wire_integers(
            value, ("schema", "sequence", "rx_bytes", "tx_bytes", "writes"),
            "Peer TCP record",
        )
        if value != {
            "schema": 1, "event": "TCP", "result": "PASS",
            "sequence": sequence, "rx_bytes": body_length + 24,
            "tx_bytes": body_length + 24, "writes": value["writes"],
        } or value["writes"] < minimum_writes:
            raise ValueError("Peer TCP record has invalid sequence, bytes, or result")
        tcp_writes.append(value["writes"])
    for (index, value), (sequence, body_length) in zip(udp, UDP_CASES):
        _exact_fields(
            value,
            ("schema", "event", "result", "sequence", "rx_bytes", "tx_bytes"),
            "Peer UDP record",
        )
        _require_wire_integers(
            value, ("schema", "sequence", "rx_bytes", "tx_bytes"),
            "Peer UDP record",
        )
        if value != {
            "schema": 1, "event": "UDP", "result": "PASS",
            "sequence": sequence, "rx_bytes": body_length + 24,
            "tx_bytes": body_length + 24,
        }:
            raise ValueError("Peer UDP record has invalid sequence, bytes, or result")
    if len(tcp) < len(TCP_CASES) or len(udp) < len(UDP_CASES) or not final:
        raise EvidenceIncomplete("Peer exchanges have not completed")

    final_index, final_value = final[0]
    _exact_fields(
        final_value,
        ("schema", "event", "result", "peer_ip", "guest_ip", "tcp_port",
         "udp_port", "nonce", "tcp_connections", "udp_datagrams",
         "tcp_rx_bytes", "tcp_tx_bytes", "tcp_writes", "udp_rx_bytes",
         "udp_tx_bytes"),
        "Peer FINAL record",
    )
    _require_wire_integers(
        final_value,
        (
            "schema", "tcp_port", "udp_port", "tcp_connections",
            "udp_datagrams", "tcp_rx_bytes", "tcp_tx_bytes", "tcp_writes",
            "udp_rx_bytes", "udp_tx_bytes",
        ),
        "Peer FINAL record",
    )
    if final_value.get("result") != "PASS":
        raise ValueError("Peer FINAL record reported failure")
    expected_counts = {
        "tcp_connections": len(TCP_CASES), "udp_datagrams": len(UDP_CASES),
        "tcp_rx_bytes": TCP_BYTES, "tcp_tx_bytes": TCP_BYTES,
        "udp_rx_bytes": UDP_BYTES, "udp_tx_bytes": UDP_BYTES,
    }
    if (
        any(final_value[key] != value for key, value in endpoint_fields.items())
        or any(final_value[key] != value for key, value in expected_counts.items())
        or final_value["tcp_writes"] != sum(tcp_writes)
    ):
        raise ValueError("Peer FINAL record does not match the exact exchange")
    if not eof:
        raise EvidenceIncomplete("Peer EOF has not appeared")
    eof_index, eof_value = eof[0]
    _exact_fields(eof_value, ("schema", "event", "exit_code"), "Peer EOF record")
    _require_wire_integers(
        eof_value, ("schema", "exit_code"), "Peer EOF record"
    )
    if eof_value != {"schema": 1, "event": "EOF", "exit_code": 0}:
        raise ValueError("Peer process did not exit successfully")
    positions = [
        start_index, ready_index, *[index for index, _ in tcp],
        *[index for index, _ in udp], final_index, eof_index,
    ]
    if positions != sorted(positions) or len(set(positions)) != len(positions):
        raise ValueError("Peer evidence is stale, duplicated, or out of order")
    return {
        "ready": {key: value for key, value in endpoint_fields.items() if key != "schema"},
        "tcp": {
            "connections": len(TCP_CASES), "rx_bytes": TCP_BYTES,
            "tx_bytes": TCP_BYTES, "writes": final_value["tcp_writes"],
        },
        "udp": {
            "datagrams": len(UDP_CASES), "rx_bytes": UDP_BYTES,
            "tx_bytes": UDP_BYTES,
        },
        "exit_code": 0,
    }


def correlate_evidence(guest_text, peer_text, acceptance, network):
    acceptance = validate_acceptance(acceptance)
    network = private_network(
        acceptance, network["guest_ipv4"], network["subnet"]
    )
    guest = inspect_guest_log(guest_text, acceptance, network)
    peer = inspect_peer_log(peer_text, acceptance, network)
    return {
        "schema": "unikraft.hyperv.network-acceptance",
        "schema_version": 1,
        "result": "PASS",
        "configuration": network,
        "transcript": acceptance["transcript"],
        "guest": guest,
        "peer": peer,
    }
