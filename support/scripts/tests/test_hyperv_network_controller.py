# SPDX-License-Identifier: BSD-3-Clause

import importlib
import json
from pathlib import Path
import sys
import unittest


SUPPORT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(SUPPORT / "scripts"))
controller = importlib.import_module("hyperv_network_controller")


class HypervNetworkControllerTest(unittest.TestCase):
    def config(self, **changes):
        values = {
            "peer": "10.87.0.4",
            "tcp": "18887",
            "udp": "18888",
            "nonce": "87c0ffee5aa8dfd6",
            "enabled": "y",
        }
        values.update(changes)
        return (
            f"CONFIG_APPHYPERVACCEPTANCE_NETWORK_APPLICATION={values['enabled']}\n"
            f'CONFIG_APPHYPERVACCEPTANCE_PEER_IPV4="{values["peer"]}"\n'
            f"CONFIG_APPHYPERVACCEPTANCE_PEER_TCP_PORT={values['tcp']}\n"
            f"CONFIG_APPHYPERVACCEPTANCE_PEER_UDP_PORT={values['udp']}\n"
            f'CONFIG_APPHYPERVACCEPTANCE_NONCE="{values["nonce"]}"\n'
        ).encode()

    def acceptance(self):
        return controller.acceptance_from_solved_config(
            self.config(), controller.PEER_SCRIPT.read_bytes()
        )

    def network(self):
        return controller.private_network(
            self.acceptance(), "10.87.0.5", "10.87.0.0/29"
        )

    @staticmethod
    def encoded(prefix, **fields):
        return prefix + json.dumps(fields, sort_keys=True)

    @staticmethod
    def producer_tcp_writes(write_limit=None):
        peer = controller._load_peer()

        class CompleteWrite:
            def settimeout(self, _timeout):
                pass

            @staticmethod
            def send(data):
                return len(data) if write_limit is None else min(len(data), write_limit)

        connection = CompleteWrite()
        nonce = int("87c0ffee5aa8dfd6", 16)
        return tuple(
            peer.send_chunks(
                connection,
                peer.message(1, 2, sequence, length, nonce),
                float("inf"),
            )
            for sequence, length in controller.TCP_CASES
        )

    @staticmethod
    def mutate_record(text, prefix, event, field, value, occurrence=0):
        lines = text.splitlines()
        matched = 0
        for index, line in enumerate(lines):
            if not line.startswith(prefix):
                continue
            record = json.loads(line[len(prefix):])
            if record.get("event") != event:
                continue
            if matched == occurrence:
                record[field] = value
                lines[index] = prefix + json.dumps(record, sort_keys=True)
                return "\n".join(lines)
            matched += 1
        raise AssertionError(f"Missing {event} occurrence {occurrence}")

    def peer_log(self):
        acceptance = self.acceptance()
        network = self.network()
        lines = [
            self.encoded(
                controller.BOOTSTRAP_PREFIX, schema=1, event="START",
                peer_script_sha256=acceptance["peer_script_sha256"],
                timeout_seconds=controller.PEER_TIMEOUT_SECONDS,
            ),
            self.encoded(
                controller.PEER_PREFIX, schema=1, event="READY",
                peer_ip=network["peer_ipv4"], guest_ip=network["guest_ipv4"],
                tcp_port=network["tcp_port"], udp_port=network["udp_port"],
                nonce=network["nonce"],
            ),
        ]
        tcp_writes = self.producer_tcp_writes()
        for (sequence, length), writes in zip(controller.TCP_CASES, tcp_writes):
            lines.append(self.encoded(
                controller.PEER_PREFIX, schema=1, event="TCP", result="PASS",
                sequence=sequence, rx_bytes=length + 24,
                tx_bytes=length + 24, writes=writes,
            ))
        for sequence, length in controller.UDP_CASES:
            lines.append(self.encoded(
                controller.PEER_PREFIX, schema=1, event="UDP", result="PASS",
                sequence=sequence, rx_bytes=length + 24,
                tx_bytes=length + 24,
            ))
        lines.extend((
            self.encoded(
                controller.PEER_PREFIX, schema=1, event="FINAL", result="PASS",
                peer_ip=network["peer_ipv4"], guest_ip=network["guest_ipv4"],
                tcp_port=network["tcp_port"], udp_port=network["udp_port"],
                nonce=network["nonce"],
                tcp_connections=3, udp_datagrams=6,
                tcp_rx_bytes=1760, tcp_tx_bytes=1760,
                tcp_writes=sum(tcp_writes),
                udp_rx_bytes=3408, udp_tx_bytes=3408,
            ),
            self.encoded(
                controller.BOOTSTRAP_PREFIX, schema=1, event="EOF", exit_code=0,
            ),
        ))
        return "\n".join(lines)

    def guest_log(self):
        acceptance = self.acceptance()
        lines = [
            "UK_HYPERV_PLATFORM_READY",
            "UK_HYPERV_BLOCK_READ_OK",
            controller.configuration_marker(acceptance),
            (
                "HYPERV_ACCEPTANCE NETWORK_APP_LEASE PASS "
                "address=10.87.0.5 netmask=255.255.255.248 "
                "gateway=10.87.0.1 mtu=1500 server=168.63.129.16 "
                "xid=1a2b3c4d state=10 retries=1 lease_seconds=3600 "
                "proof=discover-offer-request-ack-bound"
            ),
            "UK_HYPERV_NET_APP_LEASE",
            (
                "HYPERV_ACCEPTANCE NETWORK_APP_ARP PASS "
                "peer=10.87.0.4 mac=00:11:22:33:44:55 requests=1"
            ),
            "UK_HYPERV_NET_APP_ARP",
            (
                "HYPERV_ACCEPTANCE NETWORK_APP_TCP PASS "
                "connections=3 tx_messages=3 rx_messages=3 "
                "tx_bytes=1760 rx_bytes=1760 write_chunks=14 "
                "rx_callbacks=3 rx_pbuf_freed=3 close_accepted=3"
            ),
            "UK_HYPERV_NET_APP_TCP",
            (
                "HYPERV_ACCEPTANCE NETWORK_APP_UDP PASS "
                "datagrams=6 tx_bytes=3408 rx_bytes=3408 "
                "pbuf_allocated=6 pbuf_freed=6 rx_pbuf_freed=6 "
                "pcb_removed=1 unrelated=0"
            ),
            "UK_HYPERV_NET_APP_UDP",
            (
                "HYPERV_ACCEPTANCE NETWORK_APP_FINAL PASS "
                "lease=PASS arp=PASS tcp=PASS udp=PASS "
                "tcp_connections=3 udp_datagrams=6 peer_ipv4=10.87.0.4 "
                "tcp_port=18887 udp_port=18888 nonce=87c0ffee5aa8dfd6 "
                "adapter_rx_packets=12 adapter_rx_budget_exhaustions=0 "
                "adapter_tx_attempts=9 adapter_tx_busy=0"
            ),
            "UK_HYPERV_NETWORK_APP_READY",
            "UK_HYPERV_IO_READY",
            "HYPERV_ACCEPTANCE FINAL_RESULT PASS storage=PASS network=PASS",
            "[    1.234] Info: [libukboot] <boot.c @  523> main returned 0",
        ]
        return "\n".join(lines)

    def test_solved_configuration_binds_peer_and_protocol_goldens(self):
        acceptance = self.acceptance()
        self.assertEqual(acceptance["mode"], "network-application")
        self.assertEqual(
            acceptance["transcript"]["request_sha256"],
            "248e142f37352260cb00cf5a4b6847616b7140458d5b311f578aaf665ffa8a55",
        )
        self.assertEqual(
            acceptance["transcript"]["response_sha256"],
            "627d6b369079572466433da6c9f79662ec83ad4991cb6099aa94f529ce89e62a",
        )
        self.assertEqual(acceptance["transcript"]["tcp_bytes"], 1760)
        self.assertEqual(acceptance["transcript"]["udp_bytes"], 3408)

    def test_invalid_solved_endpoint_nonce_and_mode_are_rejected(self):
        for changes in (
            {"peer": "8.8.8.8"}, {"peer": "10.87.0.999"},
            {"tcp": "0"}, {"udp": "65536"}, {"tcp": "18888"},
            {"nonce": "0x87c0ffee5aa8dfd6"}, {"nonce": "bad"},
            {"enabled": "n"},
        ):
            with self.subTest(changes=changes):
                with self.assertRaises(ValueError):
                    controller.acceptance_from_solved_config(
                        self.config(**changes), controller.PEER_SCRIPT.read_bytes()
                    )

    def test_private_network_is_exact_and_avoids_azure_reservations(self):
        self.assertEqual(self.network()["gateway"], "10.87.0.1")
        for guest, subnet in (
            ("10.87.0.2", "10.87.0.0/29"),
            ("10.87.0.4", "10.87.0.0/29"),
            ("10.87.0.6", "10.87.0.0/30"),
            ("10.87.1.5", "10.87.0.0/29"),
        ):
            with self.subTest(guest=guest, subnet=subnet):
                with self.assertRaises(ValueError):
                    controller.private_network(self.acceptance(), guest, subnet)

    def test_all_preflight_logs_require_exact_config_without_live_io(self):
        marker = controller.configuration_marker(self.acceptance())
        controller.validate_preflight_log(
            f"{marker}\nUK_HYPERV_ACCEPTANCE_UNAVAILABLE:storage+network",
            self.acceptance(),
        )
        for text in (
            "UK_HYPERV_PLATFORM_READY",
            marker + "\n" + marker,
            marker + "\nUK_HYPERV_IO_READY",
            marker.replace("18887", "18889"),
        ):
            with self.subTest(text=text):
                with self.assertRaises(ValueError):
                    controller.validate_preflight_log(text, self.acceptance())

    def test_bootstrap_embeds_unchanged_peer_without_download_or_ssh(self):
        peer = controller.PEER_SCRIPT.read_bytes()
        bootstrap = controller.peer_bootstrap(
            peer, self.acceptance(), self.network()
        )
        self.assertIn("unikraft-hyperv-network-peer.service", bootstrap)
        self.assertNotIn("curl", bootstrap)
        self.assertNotIn("wget", bootstrap)
        self.assertNotIn("apt", bootstrap)
        self.assertNotIn("sshd", bootstrap)
        self.assertIn("systemctl, enable, --now", bootstrap)

    def test_correlated_peer_and_guest_streams_pass(self):
        self.assertEqual(self.producer_tcp_writes(), (2, 9, 3))
        result = controller.correlate_evidence(
            self.guest_log(), self.peer_log(),
            self.acceptance(), self.network(),
        )
        self.assertEqual(result["result"], "PASS")
        self.assertEqual(result["guest"]["tcp"]["rx_bytes"], 1760)
        self.assertEqual(result["peer"]["udp"]["tx_bytes"], 3408)
        ready_log = "\n".join(self.peer_log().splitlines()[:2])
        self.assertEqual(
            controller.inspect_peer_ready(
                ready_log, self.acceptance(), self.network()
            )["guest_ip"],
            "10.87.0.5",
        )

    def test_fixed_producer_write_minima_and_final_sum_are_required(self):
        peer = self.peer_log()
        impossible = self.mutate_record(
            peer, controller.PEER_PREFIX, "TCP", "writes", 1
        )
        impossible = self.mutate_record(
            impossible, controller.PEER_PREFIX, "FINAL", "tcp_writes", 13
        )
        inconsistent = self.mutate_record(
            peer, controller.PEER_PREFIX, "FINAL", "tcp_writes", 15
        )
        with self.assertRaisesRegex(ValueError, "TCP record"):
            controller.inspect_peer_log(
                impossible, self.acceptance(), self.network()
            )
        with self.assertRaisesRegex(ValueError, "FINAL"):
            controller.inspect_peer_log(
                inconsistent, self.acceptance(), self.network()
            )
        with self.assertRaisesRegex(ValueError, "Guest TCP"):
            controller.inspect_guest_log(
                self.guest_log().replace("write_chunks=14", "write_chunks=13"),
                self.acceptance(), self.network(),
            )

        extra = peer
        for occurrence, writes in enumerate((3, 10, 4)):
            extra = self.mutate_record(
                extra, controller.PEER_PREFIX, "TCP", "writes",
                writes, occurrence,
            )
        extra = self.mutate_record(
            extra, controller.PEER_PREFIX, "FINAL", "tcp_writes", 17
        )
        self.assertEqual(
            controller.inspect_peer_log(
                extra, self.acceptance(), self.network()
            )["tcp"]["writes"],
            17,
        )

    def test_tcp_partial_io_counts_cannot_exceed_transferred_bytes(self):
        peer = self.peer_log()
        maxima = self.producer_tcp_writes(write_limit=1)
        self.assertEqual(
            maxima, tuple(length + 24 for _, length in controller.TCP_CASES)
        )
        maximum_peer = peer
        for occurrence, writes in enumerate(maxima):
            maximum_peer = self.mutate_record(
                maximum_peer, controller.PEER_PREFIX, "TCP", "writes",
                writes, occurrence,
            )
        maximum_peer = self.mutate_record(
            maximum_peer, controller.PEER_PREFIX, "FINAL", "tcp_writes",
            sum(maxima),
        )
        result = controller.correlate_evidence(
            self.guest_log(), maximum_peer, self.acceptance(), self.network()
        )
        self.assertEqual(result["peer"]["tcp"]["writes"], controller.TCP_BYTES)

        minima = self.producer_tcp_writes()
        for occurrence, maximum in enumerate(maxima):
            impossible = self.mutate_record(
                peer, controller.PEER_PREFIX, "TCP", "writes",
                maximum + 1, occurrence,
            )
            impossible = self.mutate_record(
                impossible, controller.PEER_PREFIX, "FINAL", "tcp_writes",
                sum(minima) - minima[occurrence] + maximum + 1,
            )
            with self.subTest(peer_connection=occurrence):
                with self.assertRaisesRegex(ValueError, "Peer TCP"):
                    controller.correlate_evidence(
                        self.guest_log(), impossible,
                        self.acceptance(), self.network(),
                    )

        for field, minimum in (
            ("write_chunks", controller.TCP_MIN_WRITE_TOTAL),
            ("rx_callbacks", len(controller.TCP_CASES)),
        ):
            for count in (controller.TCP_BYTES, controller.TCP_BYTES + 1):
                guest = self.guest_log().replace(
                    f"{field}={minimum}", f"{field}={count}"
                )
                if field == "rx_callbacks":
                    guest = guest.replace(
                        f"rx_pbuf_freed={minimum}", f"rx_pbuf_freed={count}"
                    )
                with self.subTest(guest_field=field, count=count):
                    if count == controller.TCP_BYTES:
                        controller.correlate_evidence(
                            guest, peer, self.acceptance(), self.network()
                        )
                    else:
                        with self.assertRaisesRegex(ValueError, "Guest TCP"):
                            controller.correlate_evidence(
                                guest, peer, self.acceptance(), self.network()
                            )

    def test_every_peer_wire_integer_rejects_float_and_boolean_json(self):
        peer = self.peer_log()
        records = (
            (controller.BOOTSTRAP_PREFIX, "START",
             ("schema", "timeout_seconds")),
            (controller.PEER_PREFIX, "READY",
             ("schema", "tcp_port", "udp_port")),
            (controller.PEER_PREFIX, "TCP",
             ("schema", "sequence", "rx_bytes", "tx_bytes", "writes")),
            (controller.PEER_PREFIX, "UDP",
             ("schema", "sequence", "rx_bytes", "tx_bytes")),
            (controller.PEER_PREFIX, "FINAL",
             ("schema", "tcp_port", "udp_port", "tcp_connections",
              "udp_datagrams", "tcp_rx_bytes", "tcp_tx_bytes", "tcp_writes",
              "udp_rx_bytes", "udp_tx_bytes")),
            (controller.BOOTSTRAP_PREFIX, "EOF", ("schema", "exit_code")),
        )
        for prefix, event, fields in records:
            line = next(
                line for line in peer.splitlines()
                if line.startswith(prefix)
                and json.loads(line[len(prefix):]).get("event") == event
            )
            record = json.loads(line[len(prefix):])
            for field in fields:
                for invalid in (float(record[field]), record[field] == 1):
                    with self.subTest(event=event, field=field, invalid=invalid):
                        changed = self.mutate_record(
                            peer, prefix, event, field, invalid
                        )
                        with self.assertRaises(ValueError):
                            controller.inspect_peer_log(
                                changed, self.acceptance(), self.network()
                            )
                        if event in ("START", "READY"):
                            with self.assertRaises(ValueError):
                                controller.inspect_peer_ready(
                                    "\n".join(changed.splitlines()[:2]),
                                    self.acceptance(), self.network(),
                                )

    def test_only_exact_zero_main_return_record_can_complete_guest(self):
        guest = self.guest_log()
        producer = (
            "[    1.234] Info: [libukboot] "
            "<boot.c @  523> main returned 0"
        )
        normalized = (
            "\x1b[32m[    1.234] Info: [libukboot] "
            "<boot.c @  523> main returned 0\x1b[0m\0\r"
        )
        controller.inspect_guest_log(
            guest.replace(producer, normalized),
            self.acceptance(), self.network(),
        )
        variants = (
            guest.replace(
                producer,
                "diagnostic: expected main returned 0 but execution continued",
            ),
            guest.replace(producer, "Info: main returned -1"),
            guest + "\nmain returned 0",
            guest.replace(producer, "Info: main returned 0, halting"),
        )
        for value in variants:
            with self.subTest(value=value[-100:]):
                with self.assertRaises(ValueError):
                    controller.inspect_guest_log(
                        value, self.acceptance(), self.network()
                    )

    def test_peer_only_restart_failure_missing_eof_and_bad_endpoint_fail(self):
        peer = self.peer_log()
        ready = next(
            line for line in peer.splitlines()
            if '"event": "READY"' in line
        )
        variants = (
            peer + "\n" + ready,
            peer.rsplit("\n", 1)[0],
            peer.replace('"guest_ip": "10.87.0.5"', '"guest_ip": "10.87.0.6"', 1),
            peer.replace('"result": "PASS"', '"result": "FAIL"', 1),
        )
        for value in variants:
            with self.subTest(value=value[-100:]):
                with self.assertRaises((ValueError, controller.EvidenceIncomplete)):
                    controller.correlate_evidence(
                        self.guest_log(), value,
                        self.acceptance(), self.network(),
                    )
        with self.assertRaises(controller.EvidenceIncomplete):
            controller.correlate_evidence(
                "", self.peer_log(), self.acceptance(), self.network()
            )

    def test_raw_dhcp_duplicates_counts_order_and_main_return_fail(self):
        guest = self.guest_log()
        config = controller.configuration_marker(self.acceptance())
        variants = (
            guest + "\nUK_HYPERV_NET_DHCP_OFFER",
            guest + "\n" + config,
            guest.replace("tx_bytes=1760", "tx_bytes=1759", 1),
            guest.replace("adapter_tx_busy=0", "adapter_tx_busy=1"),
            guest.replace(
                "[    1.234] Info: [libukboot] "
                "<boot.c @  523> main returned 0",
                "",
            ),
            guest.replace(
                "UK_HYPERV_NET_APP_TCP\n"
                "HYPERV_ACCEPTANCE NETWORK_APP_UDP",
                "HYPERV_ACCEPTANCE NETWORK_APP_UDP",
            ) + "\nUK_HYPERV_NET_APP_TCP",
        )
        for value in variants:
            with self.subTest(value=value[-120:]):
                with self.assertRaises((ValueError, controller.EvidenceIncomplete)):
                    controller.correlate_evidence(
                        value, self.peer_log(),
                        self.acceptance(), self.network(),
                    )


if __name__ == "__main__":
    unittest.main()
