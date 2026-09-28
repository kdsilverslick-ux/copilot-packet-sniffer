"""Educational packet sniffer for traffic on this computer's loopback."""

import csv
from datetime import datetime, timezone
from pathlib import Path

from scapy.all import IP, IPv6, TCP, conf, sniff


def main():
    packet_count = 0
    output = Path(
        f"capture_{datetime.now():%Y%m%d_%H%M%S_%f}.csv"
    )

    fields = [
        "time",
        "protocol",
        "source",
        "destination",
        "source_port",
        "destination_port",
        "tcp_flags",
        "length",
    ]

    # Save metadata only: no payloads, passwords, or raw packet files.
    with output.open("x", newline="", encoding="utf-8") as file:
        writer = csv.DictWriter(file, fieldnames=fields)
        writer.writeheader()

        def process_packet(packet):
            nonlocal packet_count

            if TCP not in packet:
                return

            if IP in packet:
                protocol = "IPv4/TCP"
            elif IPv6 in packet:
                protocol = "IPv6/TCP"
            else:
                return

            packet_count += 1

            # Redact addresses before displaying or saving any results.
            row = {
                "time": datetime.fromtimestamp(
                    float(packet.time), timezone.utc
                ).isoformat(),
                "protocol": protocol,
                "source": "[REDACTED]",
                "destination": "[REDACTED]",
                "source_port": int(packet[TCP].sport),
                "destination_port": int(packet[TCP].dport),
                "tcp_flags": str(packet[TCP].flags),
                "length": len(packet),
            }

            writer.writerow(row)
            file.flush()

            print(
                f"{packet_count:02d} | {protocol} | "
                f"[REDACTED]:{row['source_port']} -> "
                f"[REDACTED]:{row['destination_port']} | "
                f"Flags: {row['tcp_flags']} | "
                f"{row['length']} bytes"
            )

        print("Capturing local TCP traffic on port 8000.")
        print("Limit: 25 packets or 60 seconds. Ctrl+C stops early.")

        try:
            sniff(
                iface=conf.loopback_name,
                filter="tcp port 8000",
                prn=process_packet,
                count=25,
                timeout=60,
                store=False,
            )
        except Exception as error:
            print(f"Capture failed: {error}")
            print("Check Npcap and capture permissions.")
            return

    print(f"\nCaptured {packet_count} packets.")
    print(f"Saved metadata to: {output.resolve()}")


if __name__ == "__main__":
    main()
    