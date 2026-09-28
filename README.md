# Copilot-Assisted Packet Sniffer: Seeing the Network (Ethically)

## Overview
This project uses Python and Scapy to capture and examine network
packet headers. It was developed with assistance from ChatGPT.

The current version captures TCP traffic on port 8000 through the
computer's loopback interface. It stops after 25 packets or 60 seconds,
whichever occurs first.

## Scope and Ethics
Capture traffic only on your own machine, loopback interface, or an
instructor-provided lab VM/network.

This demonstration uses a local web server bound to 127.0.0.1.
Do not modify this project to capture other people's traffic without
explicit authorization.

## Features
- Live capture on the loopback interface.
- BPF filter: tcp port 8000.
- IPv4/TCP and IPv6/TCP header decoding.
- UTC timestamps, ports, TCP flags, and packet lengths.
- IP addresses replaced with [REDACTED] before display or saving.
- CSV output with a unique timestamped filename.
- No saved packet payloads or raw packet capture files.
- store=False prevents Scapy from retaining a captured-packet list.

## Requirements
- Windows with Python 3.13.
- Npcap installed.
- Scapy 2.7.0, listed in requirements.txt.

## Setup
Open PowerShell in the project folder and run:

```powershell
py -3.13 -m venv .venv
.\.venv\Scripts\python.exe -m pip install -r requirements.txt
```

## Run the Demonstration
In the first terminal, start the local web server:

```powershell
.\.venv\Scripts\python.exe -m http.server 8000 --bind 127.0.0.1
```

In a second terminal, start the sniffer:

```powershell
.\.venv\Scripts\python.exe sniffer.py
```

Open http://127.0.0.1:8000 in a browser and refresh several times
while the sniffer is running.

The sniffer saves a capture_TIMESTAMP.csv file in the current directory.
Stop the web server afterward with Ctrl+C.

## How the Capture Works
- iface selects the loopback interface using conf.loopback_name.
- filter limits capture to TCP traffic involving port 8000.
- prn calls process_packet for each captured packet.
- count limits capture to 25 packets.
- timeout ends capture after 60 seconds if the limit is not reached.
- store=False avoids accumulating raw packets in a list.

The callback extracts selected header fields and writes a redacted
record to the CSV.

## Test Results
A Windows loopback test on September 28, 2026 captured 25 packets.
The saved CSV contained one header and 25 packet records.
Both address columns contained [REDACTED].

The capture showed a TCP handshake:
- S: SYN, requesting a connection.
- SA: SYN + ACK, acknowledging the connection request.
- A: ACK, completing the handshake.

Other observed flags included PA (Push + ACK) and FA (FIN + ACK).
Port 8000 identified the local web server.

## Limitations
The current version uses a fixed interface, filter, packet limit,
and timeout. It does not decode HTTP content, capture UDP/DNS,
or reconstruct application conversations.

Packet data is processed in memory, but only selected metadata is
saved. Redacting addresses does not make all metadata anonymous;
ports, timing, and packet sizes remain visible.

## AI Use Policy
This is a project-specific policy, not quoted instructor wording.

AI may assist with code generation, explanations, documentation,
and troubleshooting. The student remains responsible for reviewing
the code, understanding its behavior, and testing it in an authorized
environment.

Do not provide credentials, private payloads, or other people's
network traffic to an AI service. Describe AI assistance honestly
and do not claim tests that were not performed.

## AI Assistance Used
ChatGPT generated the initial sniffer code and provided guidance on
Windows setup, Scapy installation, loopback testing, CSV verification,
and documentation.

The student created the local files, ran the program, generated
local browser traffic, and inspected the output.

## Project Files
- sniffer.py: packet capture program.
- requirements.txt: Python dependency.
- README.md: setup, ethics, testing, and AI-use documentation.
- capture_*.csv: redacted capture results.

## Submission
Submit all project artifacts in Blackboard as instructed.
Include the source code, requirements, README, redacted sample CSV,
test screenshots, and GitHub repository link.