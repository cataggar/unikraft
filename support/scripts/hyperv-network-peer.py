#!/usr/bin/env python3
# SPDX-License-Identifier: BSD-3-Clause
"""Bounded, private-only peer for the Hyper-V UKNA v1 acceptance protocol."""

import argparse
from dataclasses import dataclass
import ipaddress
import json
import math
import re
import select
import socket
import struct
import time


HEADER = struct.Struct("!4sBBBBIIQ")
MAX_BODY = 1448
TCP_CASES = ((1, 31), (2, 1400), (3, 257))
UDP_CASES = tuple(enumerate((19, 1448, 73, 1448, 257, 19), start=0x100))
OPERATION_TIMEOUT = 5
QUIET_SECONDS = 0.2
MAX_UNEXPECTED = 16
PRIVATE_NETWORKS = tuple(map(ipaddress.IPv4Network, (
    "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16",
)))


class PeerError(ValueError):
    pass


@dataclass(frozen=True)
class Configuration:
    peer_ip: str
    guest_ip: str
    tcp_port: int
    udp_port: int
    nonce: str
    timeout: float = 300

    def __post_init__(self):
        for text in (self.peer_ip, self.guest_ip):
            if not isinstance(text, str):
                raise PeerError("invalid-address")
            try:
                address = ipaddress.IPv4Address(text)
            except ipaddress.AddressValueError as error:
                raise PeerError("invalid-address") from error
            if not any(address in network for network in PRIVATE_NETWORKS):
                raise PeerError("non-private-address")
        if self.peer_ip == self.guest_ip:
            raise PeerError("identical-endpoints")
        for port in (self.tcp_port, self.udp_port):
            if type(port) is not int or not 1 <= port <= 65535:
                raise PeerError("invalid-port")
        if not isinstance(self.nonce, str) or not re.fullmatch(
                r"[0-9a-fA-F]{16}", self.nonce):
            raise PeerError("invalid-nonce")
        if not math.isfinite(self.timeout) or not 1 <= self.timeout <= 600:
            raise PeerError("invalid-timeout")

    def public_fields(self):
        return {
            "peer_ip": self.peer_ip, "guest_ip": self.guest_ip,
            "tcp_port": self.tcp_port, "udp_port": self.udp_port,
            "nonce": self.nonce.lower(),
        }


def message(transport, direction, sequence, body_length, nonce):
    if (transport not in (1, 2) or direction not in (1, 2) or
            not 0 <= sequence <= 0xffffffff or
            not 0 <= body_length <= MAX_BODY or
            not 0 <= nonce <= 0xffffffffffffffff):
        raise PeerError("invalid-message-parameters")
    header = HEADER.pack(
        b"UKNA", 1, transport, direction, HEADER.size,
        sequence, body_length, nonce,
    )
    body = bytes(
        ((nonce >> ((7 - (offset & 7)) * 8)) ^
         (sequence >> ((3 - (offset & 3)) * 8)) ^
         (transport * 0x31) ^ (direction * 0x57) ^
         (offset * 0x1d)) & 0xff
        for offset in range(body_length)
    )
    return header + body


def remaining(deadline):
    duration = deadline - time.monotonic()
    if duration <= 0:
        raise PeerError("deadline-exceeded")
    return duration


def receive_exact(connection, length, deadline):
    data = bytearray()
    while len(data) < length:
        connection.settimeout(remaining(deadline))
        part = connection.recv(length - len(data))
        if not part:
            raise PeerError("premature-close")
        data.extend(part)
    return bytes(data)


def send_chunks(connection, data, deadline):
    offset = 0
    writes = 0
    chunks = (11, 97, 503)
    while offset < len(data):
        connection.settimeout(remaining(deadline))
        size = chunks[writes % len(chunks)]
        count = connection.send(data[offset:offset + size])
        if count == 0:
            raise PeerError("short-write")
        offset += count
        writes += 1
    return writes


def accept_guest(listener, guest_ip, deadline):
    for _ in range(MAX_UNEXPECTED + 1):
        listener.settimeout(remaining(deadline))
        connection, address = listener.accept()
        if address[0] == guest_ip:
            return connection
        connection.close()
    raise PeerError("unexpected-peer-limit")


def exchange_tcp(connection, sequence, body_length, nonce, deadline):
    expected = message(1, 1, sequence, body_length, nonce)
    if receive_exact(connection, len(expected), deadline) != expected:
        raise PeerError("invalid-tcp-request")
    response = message(1, 2, sequence, body_length, nonce)
    writes = send_chunks(connection, response, deadline)
    connection.shutdown(socket.SHUT_WR)
    # Validate the whole request stream, including bytes arriving after the
    # expected frame. The guest closes after consuming the complete response.
    connection.settimeout(remaining(deadline))
    if connection.recv(1):
        raise PeerError("extra-tcp-bytes")
    return len(expected), len(response), writes


def receive_guest_datagram(udp, guest_ip, deadline):
    for _ in range(MAX_UNEXPECTED + 1):
        udp.settimeout(remaining(deadline))
        data, address = udp.recvfrom(HEADER.size + MAX_BODY + 1)
        if address[0] == guest_ip:
            return data, address
    raise PeerError("unexpected-peer-limit")


def require_quiet(listener, udp, guest_ip, deadline):
    quiet_deadline = time.monotonic() + QUIET_SECONDS
    if quiet_deadline > deadline:
        raise PeerError("deadline-exceeded")
    unexpected = 0
    while True:
        duration = quiet_deadline - time.monotonic()
        if duration <= 0:
            return
        ready, _, _ = select.select((listener, udp), (), (), duration)
        if not ready:
            return
        for endpoint in ready:
            endpoint.settimeout(remaining(quiet_deadline))
            if endpoint is listener:
                connection, address = listener.accept()
                connection.close()
                kind = "extra-tcp-connection"
            else:
                _, address = udp.recvfrom(HEADER.size + MAX_BODY + 1)
                kind = "extra-udp-datagram"
            if address[0] == guest_ip:
                raise PeerError(kind)
            unexpected += 1
            if unexpected > MAX_UNEXPECTED:
                raise PeerError("unexpected-peer-limit")


def emit_event(event, **fields):
    record = {"schema": 1, "event": event, **fields}
    print("HYPERV_NETWORK_PEER " + json.dumps(record, sort_keys=True), flush=True)


def run(configuration, emit=emit_event):
    nonce = int(configuration.nonce, 16)
    deadline = time.monotonic() + configuration.timeout
    counts = {
        "tcp_connections": 0, "udp_datagrams": 0,
        "tcp_rx_bytes": 0, "tcp_tx_bytes": 0, "tcp_writes": 0,
        "udp_rx_bytes": 0, "udp_tx_bytes": 0,
    }
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as listener, \
            socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as udp:
        listener.bind((configuration.peer_ip, configuration.tcp_port))
        udp.bind((configuration.peer_ip, configuration.udp_port))
        listener.listen(1)
        emit("READY", **configuration.public_fields())
        for sequence, body_length in TCP_CASES:
            accept_deadline = deadline if sequence == 1 else min(
                deadline, time.monotonic() + OPERATION_TIMEOUT,
            )
            with accept_guest(
                    listener, configuration.guest_ip, accept_deadline) as connection:
                connection.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
                operation_deadline = min(
                    accept_deadline, time.monotonic() + OPERATION_TIMEOUT,
                )
                received, sent, writes = exchange_tcp(
                    connection, sequence, body_length, nonce, operation_deadline,
                )
            counts["tcp_connections"] += 1
            counts["tcp_rx_bytes"] += received
            counts["tcp_tx_bytes"] += sent
            counts["tcp_writes"] += writes
            emit("TCP", result="PASS", sequence=sequence, rx_bytes=received,
                 tx_bytes=sent, writes=writes)
        udp_address = None
        for sequence, body_length in UDP_CASES:
            operation_deadline = min(
                deadline, time.monotonic() + OPERATION_TIMEOUT,
            )
            data, address = receive_guest_datagram(
                udp, configuration.guest_ip, operation_deadline,
            )
            if udp_address is not None and address != udp_address:
                raise PeerError("udp-source-changed")
            udp_address = address
            expected = message(2, 1, sequence, body_length, nonce)
            if data != expected:
                raise PeerError("invalid-udp-request")
            response = message(2, 2, sequence, body_length, nonce)
            udp.settimeout(remaining(operation_deadline))
            if udp.sendto(response, address) != len(response):
                raise PeerError("short-datagram-write")
            counts["udp_datagrams"] += 1
            counts["udp_rx_bytes"] += len(data)
            counts["udp_tx_bytes"] += len(response)
            emit("UDP", result="PASS", sequence=sequence, rx_bytes=len(data),
                 tx_bytes=len(response))
        require_quiet(listener, udp, configuration.guest_ip, deadline)
    emit("FINAL", result="PASS", **configuration.public_fields(), **counts)
    return counts


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--peer-ip", required=True)
    parser.add_argument("--guest-ip", required=True)
    parser.add_argument("--tcp-port", type=int, default=18887)
    parser.add_argument("--udp-port", type=int, default=18888)
    parser.add_argument("--nonce", required=True)
    parser.add_argument("--timeout", type=float, default=300)
    args = parser.parse_args(argv)
    configuration = None
    try:
        configuration = Configuration(**vars(args))
        run(configuration)
    except (PeerError, TimeoutError, OSError) as error:
        fields = configuration.public_fields() if configuration is not None else {}
        if isinstance(error, PeerError):
            reason = str(error)
        elif isinstance(error, TimeoutError):
            reason = "deadline-exceeded"
        else:
            reason = "socket-error"
        emit_event("FINAL", result="FAIL", reason=reason, **fields)
        return 1
    except KeyboardInterrupt:
        emit_event("FINAL", result="FAIL", reason="interrupted")
        return 130
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
