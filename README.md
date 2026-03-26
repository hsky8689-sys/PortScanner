# High-Performance Custom Network Scanner

![C](https://img.shields.io/badge/Language-C-blue.svg)
![Platform](https://img.shields.io/badge/Platform-Linux-lightgrey.svg)
![Network](https://img.shields.io/badge/Category-Network_Security-red.svg)

## 📌 Overview
A high-performance, system-level network port scanner built from scratch in **C** for Linux environments. This project was developed to deeply explore low-level networking, Linux system programming, and the TCP/IP protocol suite. 

Unlike standard wrapper scripts, this tool crafts custom IP and TCP packets using **Raw Sockets** and leverages **libpcap** with **BPF (Berkeley Packet Filter)** for high-speed, asynchronous response capture, rivaling the mechanics of industry-standard tools like Nmap.

## 🚀 Key Features
* **Custom Packet Crafting:** Manual construction of IP and TCP headers, including accurate bit-level flag manipulation and rigorous TCP/IP Checksum calculations (handling pseudo-headers and padding).
* **Stealth Scanning Techniques:** Supports multiple scan types that bypass standard full TCP handshakes:
  * `SYN` (Half-open scanning)
  * `FIN`
  * `XMAS` (FIN, PSH, URG flags)
  * `NULL` (No flags)
* **High-Speed Asynchronous Capture:** Replaced traditional blocking `recvfrom` loops with `libpcap` event-driven packet capture.
* **Kernel-Level Filtering:** Utilizes compiled BPF (Berkeley Packet Filter) rules to drop irrelevant traffic at the kernel level, drastically reducing CPU load and preventing packet loss during massive port sweeps (e.g., 1-65535).
* **Process & Thread Management:** Implements `fork()` and POSIX threads (`pthreads`) to decouple the packet transmission engine from the listening/capture engine, scaling efficiently across large port ranges.
* **Security & Reliability:** Uses sequence/acknowledgment cookie validation to prevent false positives from network backscatter or spoofed packets.

## 🛠️ Architecture
The scanner operates on a decoupled architecture:
1. **Transmitter Engine (Raw Sockets):** Iterates through the target port range, injecting custom-crafted packets directly into the network stack.
2. **Listener Engine (libpcap):** Runs in a separate thread/process, capturing traffic promiscuously. It applies a BPF filter (`tcp and src host <target>`) and validates the sequence numbers of incoming `SYN-ACK` or `RST` packets to determine port states.

## ⚙️ Prerequisites
To compile and run this project, you need a Linux environment with the `gcc` compiler and the `libpcap` development headers installed.

**Debian/Ubuntu:**

sudo apt-get update
sudo apt-get install build-essential libpcap-dev

💻 Usage
Note: Because this tool uses Raw Sockets and promiscuous network capture, it requires root (sudo) privileges to execute.

sudo ./scanner <target_ip> <start_port> <end_port> <scan_type>

⚠️ Disclaimer
This tool is for educational purposes and authorized testing only. Do not use it against networks or systems you do not own or have explicit permission to test.
