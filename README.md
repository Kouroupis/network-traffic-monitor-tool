# Network Traffic Monitoring Tool

## Contributors    
- **Name** Adam Giaourtas 
    - **AM** 2019030106
- **Name** Alexandros Goridaris 
    - **AM** 2019030108

## Overview

This is a networking monitoring tool that utilizes the packet capture library (libpcap), 
written on the C programming language. The traffic can be processed in `online mode`, by
monitoring live from a network interface, and in `offline mode`, by reading a pcap file.
The tool supports `IPv4 / IPv6` `TCP` and `UDP` protocols. 

## Implementation

- The program starts capturing / reading packets using `pcap_open_online()` or `pcap_open_offline()`, depending on the user input. 
- The packets captured are processed by repeatedly calling `packet_handler()` through `pcap_loop()`.
- Source and destination IP and protocol are extracted using `decode_IPV4()` / `decode_IPV6()`.
- The `decode_TCP()` and `decode_UDP()` functions are used to get source and destination ports and calculate header_length, payload_length and payload_address. Non TCP or UDP packets are skipped.
- Filtering is applied if specified by user.
- Retransmission detection is **not implemented**.
- Information about each packet's IP addresses, ports, protocol, header length and payload length and address are printed on the console and `online_output.txt` / `offline_output.txt`.
- On exit, statistics about flows captured and packets received are printed on the console and output files.

## Theoritical Questions
> 1. Can you tell if an incoming TCP packet is a retransmission? If yes, how? If not, why?

> 2. Can you tell if an incoming UDP packet is a retransmission? If yes, how? If not, why?
## Tool Specification

The tool accepts the following command-line arguements:
- `-i <interface>`: Select the network interface name (e.g. eth0).
- `-r <packet_capture>`: Packet capture file name (e.g. test.pcap).
- `-f <filter>`: Filter expression in string format (e.g. port 8080).
- `-h <help>`: Help message. 
 
 ### Examples of execution
 >You will need sudo permission in order to capture real time traffic.
 ```bash
 sudo ./pcap_ex -i eth0
 ```
 ```bash
 ./pcap_ex -r mirai.pcap
 ```
 ```bash
 ./pcap_ex -r mirai.pcap -f "port 80"
 ```

 ### Setup
 To compile, use the Makefile:
 ```bash
 make
 ```