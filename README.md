# vajrip - A Userspace TCP/IP Protocol Stack Implementation

![vajrip](https://img.shields.io/badge/vajrip-TCP%2FIP%20Stack-blue)

## Introduction

**Vajrip** is a complete implementation of a TCP/IP protocol stack designed for educational purposes. Written entirely in C, it implements all major networking protocols in userspace while maintaining minimal operating system dependencies.

### Key Features

- **Complete TCP/IP Stack**: Implements everything from Ethernet to TCP in userspace
- **Educational Focus**: Transparent packet flow and protocol state visibility
- **Multiple Devices**: Null, Loopback, and Ethernet TAP device support
- **Socket API**: BSD socket-compatible interface for applications
- **Portable**: Runs on Linux, xv6, and MikanOS

### Quick Start

### Prerequisites

```bash
# Ubuntu/Debian
sudo apt update
sudo apt install build-essential git tcpdump net-tools

# CentOS/RHEL
sudo yum groupinstall "Development Tools"
```

### Installation & Demo

```bash
# Clone and build
git clone https://github.com/yourusername/vajrip.git
cd vajrip
make

# Setup network interface
sudo ip tuntap add mode tap user $USER name tap0
sudo ip addr add 192.0.2.1/24 dev tap0
sudo ip link set tap0 up

# Run TCP echo server
./app/tcps.exe 7

# In another terminal, test connectivity
ping 192.0.2.2
echo "Hello vajrip!" | nc 192.0.2.2 7
```

## Architecture Overview

vajrip implements a complete network stack in userspace:

```
Application Layer
    ↓ (Socket API)
Transport Layer (TCP/UDP)
    ↓ (Segments/Datagrams)
Network Layer (IP/ICMP/ARP)
    ↓ (Packets)
Data Link Layer (Ethernet)
    ↓ (Frames)
Physical Layer (TAP Device)
```

### Core Components

- **Device Abstraction**: Uniform interface for multiple device types
- **Protocol Handlers**: Modular protocol processing (ARP, IP, ICMP, UDP, TCP)
- **Buffer Management**: Efficient packet buffer allocation and recycling
- **Timer System**: Protocol timeouts and retransmission handling

## Protocol Support

### Implemented Protocols

| Layer | Protocols | Features |
|-------|-----------|----------|
| Data Link | Ethernet | Frame handling, MAC addressing, TAP driver |
| Network | ARP | Address resolution, cache management |
| Network | IP | Packet routing, fragmentation, TTL processing |
| Network | ICMP | Echo (ping), error messages |
| Transport | UDP | Datagram service, port multiplexing |
| Transport | TCP | Connection management, flow control, congestion control |

### TCP Implementation Details

vajrip implements the full TCP specification:
- Three-way handshake connection establishment
- Sliding window flow control
- Sequence number generation and acknowledgment
- Retransmission with exponential backoff
- Connection termination (FIN handshake)

## API Reference

### Socket-like Interface

```c
/* BSD socket compatible API */
int vajrip_socket(int domain, int type, int protocol);
int vajrip_bind(int sockfd, const struct sockaddr *addr, socklen_t addrlen);
int vajrip_listen(int sockfd, int backlog);
int vajrip_accept(int sockfd, struct sockaddr *addr, socklen_t *addrlen);
ssize_t vajrip_send(int sockfd, const void *buf, size_t len, int flags);
ssize_t vajrip_recv(int sockfd, void *buf, size_t len, int flags);
int vajrip_close(int sockfd);
```

### Management APIs

```c
/* Network configuration */
int vajrip_iface_add(const char *devname, const char *addr, const char *netmask);
int vajrip_route_add(const char *network, const char *netmask, const char *gateway);

/* Statistics and debugging */
void vajrip_stats(void);
void vajrip_set_debug_level(int level);
```

## Sample Applications

### TCP Echo Server
```bash
./app/tcps.exe <port>
# Listens on specified port, echoes back all received data
```

### UDP Echo Server
```bash
./app/udps.exe <port>
# UDP version of echo service
```

## Development Guide

### Project Structure
```
vajrip/
├── app/                           # Sample Applications
│   ├── tcpc.c                     # TCP Client Implementation
│   ├── tcps.c                     # TCP Server Implementation  
│   ├── udpc.c                     # UDP Client Implementation
│   └── udps.c                     # UDP Server Implementation
├── driver/                        # Network Device Drivers
│   ├── ether_pcap.h               # PCAP Ethernet Driver Header
│   ├── ether_tap.h                # TAP Ethernet Driver Header
│   ├── loopback.c                 # Loopback Device Implementation
│   ├── loopback.h                 # Loopback Device Header
│   ├── null.c                     # Null Device Implementation
│   └── null.h                     # Null Device Header
├── platform/                      # Platform-Specific Code
│   └── linux/                     # Linux Platform Implementation
│       ├── driver/                # Linux-Specific Drivers
│       │   ├── ether_pcap.c       # Linux PCAP Ethernet Driver
│       │   └── ether_tap.c        # Linux TAP Ethernet Driver
│       ├── intr.c                 # Interrupt Handling
│       ├── platform.h             # Platform Definitions
│       └── sched.c                # Scheduler Implementation
├── test/                          # Test Suite
│   ├── test.c                     # Test Implementation
│   └── test.h                     # Test Framework Header
├── Core Protocol Implementation Files
├── arp.c                          # ARP Protocol Implementation
├── arp.h                          # ARP Protocol Header
├── ether.c                        # Ethernet Protocol Implementation  
├── ether.h                        # Ethernet Protocol Header
├── icmp.c                         # ICMP Protocol Implementation
├── icmp.h                         # ICMP Protocol Header
├── ip.c                           # IP Protocol Implementation
├── ip.h                           # IP Protocol Header
├── net.c                          # Core Networking Infrastructure
├── net.h                          # Core Networking Headers
├── sock.c                         # Socket API Implementation
├── sock.h                         # Socket API Headers
├── tcp.c                          # TCP Protocol Implementation
├── tcp.h                          # TCP Protocol Header
├── udp.c                          # UDP Protocol Implementation
├── udp.h                          # UDP Protocol Header
├── Utility Files
├── util.c                         # Utility Functions
├── util.h                         # Utility Headers
├── compile_flags.txt              # Compilation Configuration
├── Makefile                       # Build System
└── README.md                      # Project Documentation
```

### Adding New Protocols

1. **Register protocol handler**:
```c
net_protocol_register(ETH_P_NEWPROTO, newproto_input);
```

2. **Implement protocol logic**:
```c
static void newproto_input(const uint8_t *data, size_t len, 
                          struct net_device *dev) {
    // Parse protocol headers
    // Process according to specification
    // Generate responses if needed
}
```

## Troubleshooting

### Common Issues

**TAP device permissions:**
```bash
sudo chown $USER /dev/net/tun
```

**Device already exists:**
```bash
sudo ip link delete tap0
```

**Build failures:**
```bash
make clean
make
```

**No network connectivity:**
```bash
# Verify TAP device
ip link show tap0
ip addr show tap0

# Check routing
ip route show
```

### Debugging Tips

1. **Enable verbose logging**: Set debug level in source code
2. **Monitor TAP traffic**: `sudo tcpdump -i tap0 -n`
3. **Check protocol states**: Use built-in statistics output
4. **Validate configuration**: Verify IP addresses and routes

## Testing

### Manual Testing
```bash
# Basic connectivity
ping 192.0.2.2

# TCP functionality
nc 192.0.2.2 7

# UDP functionality
nc -u 192.0.2.2 7
```

## Resources

### Protocol References
- [RFC 791](https://tools.ietf.org/html/rfc791) - Internet Protocol
- [RFC 793](https://tools.ietf.org/html/rfc793) - Transmission Control Protocol  
- [RFC 826](https://tools.ietf.org/html/rfc826) - Ethernet Address Resolution Protocol

## Contributing

We welcome contributions! Areas of particular interest:
- IPv6 support
- Additional transport protocols
- Performance optimizations
- New device drivers
- Enhanced testing

### Development Setup
1. Fork the repository
2. Create a feature branch
3. Make changes with tests
4. Submit pull request

## Acknowledgments
- TCP/IP protocol specifications by IETF
- TUN/TAP driver support in Linux kernel
- Myself. I did it all.

---

**vajrip** - Understanding TCP/IP from scratch