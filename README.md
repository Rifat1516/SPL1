# SPL1
PackAnalyzer is a lightweight, educational command line and graphical network packet analysis tool developed in C using the libpcap library. It is designed to simplify the learning process of network traffic capture and analysis, providing an accessible alternative to complex tools like Wireshark.

Key Features:
Real-Time Packet Capture: Captures live network packets from user-specified interfaces such as Ethernet or Wi-Fi. It operates in promiscuous mode to intercept all packets traversing the selected interface.
Offline Analysis: Supports reading and parsing of pre-captured packet trace files in standard .pcap and .pcapngformats. This facilitates retrospective analysis without an active connection.
Layered Protocol Decoding: Implements a hierarchical decoding model reflecting the OSI network model. Ethernet (Layer 2): Extracts Source/Destination MAC addresses and EtherType. IP (Layer 3): Interprets IPv4 and IPv6 headers, including IP addresses, protocol identifiers, and TTL values. TCP/UDP (Layer 4): Identifies Source/Destination Port numbers and transport layer insights. Payload Visualization: Provides a dual-format hexadecimal and ASCII representation of each packet's payload for deep inspection. Security Features: Includes a module for SYN Flood attack detection and simulation.
Graphical User Interface (GUI): A Python-based interface for easier interaction and visualization.

Tech Stack:
Primary Language: C  
Core Library: libpcap Build System
Make  GUI: C
Supporting Tools: Wireshark  
