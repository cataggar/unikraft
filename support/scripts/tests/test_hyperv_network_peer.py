# SPDX-License-Identifier: BSD-3-Clause

from concurrent.futures import ThreadPoolExecutor
import hashlib
import importlib
import io
import json
from pathlib import Path
import socket
import sys
import time
import unittest
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
peer = importlib.import_module("hyperv-network-peer")

NONCE = 0x87c0ffee5aa8dfd6
GUEST = "10.87.0.5"


class Stream:
    def __init__(self, incoming, chunk=17):
        self.incoming = bytearray(incoming)
        self.chunk = chunk
        self.outgoing = bytearray()
        self.timeouts = []
        self.receives = 0
        self.closed = False
        self.shutdown_how = None

    def __enter__(self):
        return self

    def __exit__(self, *_):
        self.close()

    def close(self):
        self.closed = True

    def setsockopt(self, *_):
        pass

    def settimeout(self, timeout):
        self.timeouts.append(timeout)

    def recv(self, size):
        self.receives += 1
        size = min(size, self.chunk)
        result = bytes(self.incoming[:size])
        del self.incoming[:size]
        return result

    def send(self, data):
        data = data[:self.chunk]
        self.outgoing.extend(data)
        return len(data)

    def shutdown(self, how):
        self.shutdown_how = how


class HypervNetworkPeerTest(unittest.TestCase):
    def configuration(self, **overrides):
        values = {
            "peer_ip": "10.87.0.4", "guest_ip": GUEST,
            "tcp_port": 18887, "udp_port": 18888,
            "nonce": "87c0ffee5aa8dfd6",
        }
        return peer.Configuration(**(values | overrides))

    def fixtures(self):
        connections = [
            Stream(peer.message(1, 1, sequence, length, NONCE))
            for sequence, length in peer.TCP_CASES
        ]
        listener = mock.MagicMock()
        listener.__enter__.return_value = listener
        listener.accept.side_effect = [(connection, (GUEST, 40000 + index))
                                       for index, connection in enumerate(connections)]
        udp = mock.MagicMock()
        udp.__enter__.return_value = udp
        datagrams = [
            (peer.message(2, 1, sequence, length, NONCE), (GUEST, 41000))
            for sequence, length in peer.UDP_CASES
        ]
        udp.recvfrom.side_effect = datagrams
        udp.sendto.side_effect = lambda data, _: len(data)
        return connections, listener, udp, datagrams

    def execute(self, listener, udp):
        records = []
        with mock.patch.object(peer.socket, "socket", side_effect=[listener, udp]), \
                mock.patch.object(peer.select, "select", return_value=([], [], [])):
            counts = peer.run(
                self.configuration(),
                lambda event, **fields: records.append({"event": event, **fields}),
            )
        return counts, records

    def test_explicit_private_configuration_and_bounded_timeout(self):
        for field, value in (
            ("peer_ip", "0.0.0.0"), ("peer_ip", "127.0.0.1"),
            ("peer_ip", "169.254.0.4"), ("guest_ip", "8.8.8.8"),
            ("guest_ip", "::1"), ("guest_ip", "10.87.0.4"),
            ("nonce", "0x87c0ffee5aa8dfd6"), ("nonce", "z" * 16),
            ("tcp_port", 0), ("udp_port", 65536), ("tcp_port", True),
            ("timeout", 0), ("timeout", 601),
            ("timeout", float("inf")), ("timeout", float("nan")),
        ):
            with self.subTest(field=field, value=value):
                with self.assertRaises(peer.PeerError):
                    self.configuration(**{field: value})
        self.assertEqual(self.configuration(
            nonce="87C0FFEE5AA8DFD6").public_fields()["nonce"], "87c0ffee5aa8dfd6")

    def test_wire_header_and_direction_specific_body(self):
        request = peer.message(1, 1, 1, 31, NONCE)
        self.assertEqual(request[:24], bytes.fromhex(
            "554b4e4101010118000000010000001f87c0ffee5aa8dfd6"))
        self.assertNotEqual(request[24:], peer.message(1, 2, 1, 31, NONCE)[24:])
        self.assertEqual(len(peer.message(2, 1, 0x101, 1448, NONCE)), 1472)
        with self.assertRaises(peer.PeerError):
            peer.message(2, 1, 0, 1449, NONCE)

    def test_complete_matrix_matches_guest_c_serializer_goldens(self):
        # Generated independently with hyperv_acceptance_app_build in the
        # guest C implementation, concatenating TCP then UDP for each direction.
        goldens = (
            "248e142f37352260cb00cf5a4b6847616b7140458d5b311f578aaf665ffa8a55",
            "627d6b369079572466433da6c9f79662ec83ad4991cb6099aa94f529ce89e62a",
        )
        for direction, golden in enumerate(goldens, start=1):
            data = b"".join(
                peer.message(transport, direction, sequence, length, NONCE)
                for transport, cases in ((1, peer.TCP_CASES), (2, peer.UDP_CASES))
                for sequence, length in cases
            )
            self.assertEqual(len(data), 5168)
            self.assertEqual(hashlib.sha256(data).hexdigest(), golden)

    def test_exact_matrix_and_partial_stream_io(self):
        connections, listener, udp, _ = self.fixtures()
        counts, records = self.execute(listener, udp)
        self.assertEqual(counts["tcp_connections"], 3)
        self.assertEqual(counts["udp_datagrams"], 6)
        self.assertEqual(counts["tcp_rx_bytes"], 1760)
        self.assertEqual(counts["tcp_tx_bytes"], 1760)
        self.assertEqual(counts["udp_rx_bytes"], 3408)
        self.assertEqual(counts["udp_tx_bytes"], 3408)
        listener.bind.assert_called_once_with(("10.87.0.4", 18887))
        udp.bind.assert_called_once_with(("10.87.0.4", 18888))
        listener.listen.assert_called_once_with(1)
        for connection, (sequence, length) in zip(connections, peer.TCP_CASES):
            self.assertEqual(connection.outgoing,
                             peer.message(1, 2, sequence, length, NONCE))
            self.assertTrue(connection.closed)
            self.assertEqual(connection.shutdown_how, socket.SHUT_WR)
        for call, (sequence, length) in zip(udp.sendto.call_args_list, peer.UDP_CASES):
            self.assertEqual(call.args, (
                peer.message(2, 2, sequence, length, NONCE), (GUEST, 41000),
            ))
        self.assertEqual(records[0]["event"], "READY")
        self.assertEqual(records[-1]["event"], "FINAL")
        self.assertEqual(records[-1]["result"], "PASS")
        self.assertEqual(records[-1]["nonce"], "87c0ffee5aa8dfd6")
        listener.__exit__.assert_called_once()
        udp.__exit__.assert_called_once()

    def test_bad_or_trailing_tcp_data_cannot_pass(self):
        valid = peer.message(1, 1, 1, 31, NONCE)
        variants = [valid[:-1], valid + b"extra"]
        for offset in (0, 4, 5, 6, 7, 8, 12, 16, 24):
            changed = bytearray(valid)
            changed[offset] ^= 1
            variants.append(bytes(changed))
        for data in variants:
            with self.subTest(data=data.hex()):
                with self.assertRaises(peer.PeerError):
                    peer.exchange_tcp(Stream(data), 1, 31, NONCE,
                                      time.monotonic() + 1)

    def test_udp_corruption_duplicates_reordering_and_source_changes_fail(self):
        for fault in ("corrupt", "duplicate", "reorder", "truncate", "extra", "source"):
            with self.subTest(fault=fault):
                connections, listener, udp, datagrams = self.fixtures()
                if fault == "duplicate":
                    datagrams[1] = datagrams[0]
                elif fault == "reorder":
                    datagrams[0], datagrams[1] = datagrams[1], datagrams[0]
                elif fault == "source":
                    datagrams[1] = (datagrams[1][0], (GUEST, 41001))
                else:
                    data, address = datagrams[1]
                    if fault == "corrupt":
                        data = data[:-1] + bytes([data[-1] ^ 1])
                    elif fault == "truncate":
                        data = data[:-1]
                    else:
                        data += b"extra"
                    datagrams[1] = data, address
                udp.recvfrom.side_effect = datagrams
                with self.assertRaises(peer.PeerError):
                    self.execute(listener, udp)
                listener.__exit__.assert_called_once()
                udp.__exit__.assert_called_once()
                self.assertTrue(all(connection.closed for connection in connections))

    def test_partial_reads_and_writes_do_not_reset_deadline(self):
        for operation in ("read", "write"):
            with self.subTest(operation=operation):
                stream = Stream(b"abc", chunk=1)
                with mock.patch.object(peer.time, "monotonic", side_effect=[0, 1, 5]):
                    with self.assertRaisesRegex(peer.PeerError, "deadline-exceeded"):
                        if operation == "read":
                            peer.receive_exact(stream, 3, 5)
                        else:
                            peer.send_chunks(stream, b"abc", 5)
                self.assertEqual(stream.timeouts, [5, 4])

    def test_foreign_sender_floods_are_bounded(self):
        udp = mock.Mock()
        udp.recvfrom.return_value = (b"noise", ("10.87.0.9", 41000))
        listener = mock.Mock()
        connection = mock.Mock()
        listener.accept.return_value = (connection, ("10.87.0.9", 41000))
        with mock.patch.object(peer.time, "monotonic", return_value=0):
            with self.assertRaisesRegex(peer.PeerError, "unexpected-peer-limit"):
                peer.receive_guest_datagram(udp, GUEST, 5)
            with self.assertRaisesRegex(peer.PeerError, "unexpected-peer-limit"):
                peer.accept_guest(listener, GUEST, 5)
        self.assertEqual(udp.recvfrom.call_count, peer.MAX_UNEXPECTED + 1)
        self.assertEqual(listener.accept.call_count, peer.MAX_UNEXPECTED + 1)
        self.assertEqual(connection.close.call_count, peer.MAX_UNEXPECTED + 1)

    def test_pending_extra_peer_traffic_fails_before_final_result(self):
        listener = mock.Mock()
        udp = mock.Mock()
        connection = mock.Mock()
        listener.accept.return_value = (connection, (GUEST, 41000))
        udp.recvfrom.return_value = (b"duplicate", (GUEST, 41000))
        for endpoint, reason in ((listener, "extra-tcp"), (udp, "extra-udp")):
            with self.subTest(reason=reason):
                with mock.patch.object(peer.select, "select",
                                       return_value=([endpoint], [], [])):
                    with self.assertRaisesRegex(peer.PeerError, reason):
                        peer.require_quiet(listener, udp, GUEST, time.monotonic() + 1)
        connection.close.assert_called_once()

    def test_quiet_period_flood_is_bounded(self):
        listener = mock.Mock()
        udp = mock.Mock()
        udp.recvfrom.return_value = (b"noise", ("10.87.0.9", 41000))
        with mock.patch.object(peer.time, "monotonic", return_value=0), \
                mock.patch.object(peer.select, "select", return_value=([udp], [], [])):
            with self.assertRaisesRegex(peer.PeerError, "unexpected-peer-limit"):
                peer.require_quiet(listener, udp, GUEST, 5)
        self.assertEqual(udp.recvfrom.call_count, peer.MAX_UNEXPECTED + 1)

    def test_bind_failure_closes_sockets_without_readiness(self):
        _, listener, udp, _ = self.fixtures()
        udp.bind.side_effect = OSError("bind failed")
        emit = mock.Mock()
        with mock.patch.object(peer.socket, "socket", side_effect=[listener, udp]):
            with self.assertRaises(OSError):
                peer.run(self.configuration(), emit)
        emit.assert_not_called()
        listener.__exit__.assert_called_once()
        udp.__exit__.assert_called_once()

    def test_peer_timeout_closes_sockets_and_cannot_report_final_pass(self):
        _, listener, udp, _ = self.fixtures()
        listener.accept.side_effect = TimeoutError()
        records = []
        with mock.patch.object(peer.socket, "socket", side_effect=[listener, udp]):
            with self.assertRaises(TimeoutError):
                peer.run(self.configuration(), lambda event, **_: records.append(event))
        self.assertEqual(records, ["READY"])
        listener.__exit__.assert_called_once()
        udp.__exit__.assert_called_once()

    def test_socketpair_full_duplex_exchange_and_clean_eof(self):
        request = peer.message(1, 1, 2, 1400, NONCE)
        client, server = socket.socketpair()
        with client, server, ThreadPoolExecutor(max_workers=1) as workers:
            client.settimeout(2)

            def guest():
                for offset in range(0, len(request), 7):
                    client.sendall(request[offset:offset + 7])
                response = bytearray()
                while True:
                    part = client.recv(13)
                    if not part:
                        break
                    response.extend(part)
                client.shutdown(socket.SHUT_WR)
                return bytes(response)

            result = workers.submit(guest)
            received, sent, writes = peer.exchange_tcp(
                server, 2, 1400, NONCE, time.monotonic() + 2,
            )
            self.assertEqual(result.result(timeout=2),
                             peer.message(1, 2, 2, 1400, NONCE))
            self.assertEqual((received, sent), (1424, 1424))
            self.assertGreater(writes, 1)

    def test_zero_stream_write_and_short_datagram_write_fail(self):
        connection = mock.Mock()
        connection.send.return_value = 0
        with self.assertRaisesRegex(peer.PeerError, "short-write"):
            peer.send_chunks(connection, b"abc", time.monotonic() + 1)
        _, listener, udp, _ = self.fixtures()
        udp.sendto.side_effect = lambda data, _: len(data) - 1
        with self.assertRaisesRegex(peer.PeerError, "short-datagram-write"):
            self.execute(listener, udp)
        listener.__exit__.assert_called_once()
        udp.__exit__.assert_called_once()

    def test_failure_is_explicit_and_contains_no_exception_details(self):
        arguments = [
            "--peer-ip", "10.87.0.4", "--guest-ip", GUEST,
            "--nonce", "87c0ffee5aa8dfd6",
        ]
        output = io.StringIO()
        with mock.patch.object(peer, "run", side_effect=OSError("private details")), \
                mock.patch("sys.stdout", output):
            self.assertEqual(peer.main(arguments), 1)
        self.assertNotIn("private details", output.getvalue())
        record = json.loads(output.getvalue().split(" ", 1)[1])
        self.assertEqual((record["event"], record["result"]), ("FINAL", "FAIL"))
        self.assertEqual(record["reason"], "socket-error")


if __name__ == "__main__":
    unittest.main()
