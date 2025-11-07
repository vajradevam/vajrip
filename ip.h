/**
 * @file ip.h
 * @brief IP (Internet Protocol) definitions and interfaces
 * 
 * Provides IPv4 protocol functionality including addressing, routing,
 * interface management, and protocol handling for TCP/IP implementations.
 */

#ifndef IP_H
#define IP_H

#include <stddef.h>
#include <stdint.h>
#include <sys/types.h>

#include "net.h"

/* IP protocol version */
#define IP_VERSION_IPV4 4

/* IP header size constraints */
#define IP_HDR_SIZE_MIN 20  /* Minimum IP header size (no options) */
#define IP_HDR_SIZE_MAX 60  /* Maximum IP header size (with options) */

/* IP packet size constraints */
#define IP_TOTAL_SIZE_MAX UINT16_MAX  /* Maximum IP packet size (including header) */
#define IP_PAYLOAD_SIZE_MAX (IP_TOTAL_SIZE_MAX - IP_HDR_SIZE_MIN)  /* Max payload size */

/* IP address configuration */
#define IP_ADDR_LEN 4                 /* IPv4 address length in bytes */
#define IP_ADDR_STR_LEN 16            /* String representation: "ddd.ddd.ddd.ddd\0" */
#define IP_ENDPOINT_STR_LEN (IP_ADDR_STR_LEN + 6)  /* "xxx.xxx.xxx.xxx:yyyyy\0" */

/* 
 * IP protocol numbers
 * See: https://www.iana.org/assignments/protocol-numbers/protocol-numbers.txt
 */
#define IP_PROTOCOL_ICMP 0x01  /* Internet Control Message Protocol */
#define IP_PROTOCOL_TCP  0x06  /* Transmission Control Protocol */
#define IP_PROTOCOL_UDP  0x11  /* User Datagram Protocol */

/* IPv4 address type (32-bit integer in network byte order) */
typedef uint32_t ip_addr_t;

/**
 * @brief IP endpoint structure (address + port)
 * 
 * Used for socket-like addressing in higher layer protocols.
 */
struct ip_endpoint {
    ip_addr_t addr;  /* IP address in network byte order */
    uint16_t port;   /* Port number in network byte order */
};

/**
 * @brief IP interface structure
 * 
 * Represents a network interface with IP configuration including
 * address, netmask, and broadcast address.
 */
struct ip_iface {
    struct net_iface iface;    /* Base network interface */
    struct ip_iface *next;     /* Next interface in linked list */
    ip_addr_t unicast;         /* Interface IP address */
    ip_addr_t netmask;         /* Network mask */
    ip_addr_t broadcast;       /* Broadcast address */
};

/* Special IP address constants */
extern const ip_addr_t IP_ADDR_ANY;          /* 0.0.0.0 - any address */
extern const ip_addr_t IP_ADDR_BROADCAST;    /* 255.255.255.255 - limited broadcast */

/* ============================================================================
 * IP Address Conversion Functions
 * ============================================================================

/**
 * @brief Convert IP address from text to binary form
 * @param p String representation (e.g., "192.168.1.1")
 * @param n Output buffer for binary IP address
 * @return 0 on success, -1 on failure
 */
extern int ip_addr_pton(const char *p, ip_addr_t *n);

/**
 * @brief Convert IP address from binary to text form
 * @param n Binary IP address to convert
 * @param p Output buffer for string representation
 * @param size Size of output buffer (should be at least IP_ADDR_STR_LEN)
 * @return Pointer to string representation, NULL on failure
 */
extern char *ip_addr_ntop(const ip_addr_t n, char *p, size_t size);

/**
 * @brief Convert IP endpoint from text to binary form
 * @param p String representation (e.g., "192.168.1.1:80")
 * @param n Output structure for binary endpoint
 * @return 0 on success, -1 on failure
 */
extern int ip_endpoint_pton(const char *p, struct ip_endpoint *n);

/**
 * @brief Convert IP endpoint from binary to text form
 * @param n Binary endpoint structure to convert
 * @param p Output buffer for string representation
 * @param size Size of output buffer (should be at least IP_ENDPOINT_STR_LEN)
 * @return Pointer to string representation, NULL on failure
 */
extern char *ip_endpoint_ntop(const struct ip_endpoint *n, char *p, size_t size);

/* ============================================================================
 * IP Routing Functions
 * ============================================================================

/**
 * @brief Set default gateway for routing
 * @param iface Network interface to set as default route
 * @param gateway Gateway IP address in string form
 * @return 0 on success, -1 on failure
 */
extern int ip_route_set_default_gateway(struct ip_iface *iface, const char *gateway);

/**
 * @brief Get appropriate interface for destination IP address
 * @param dst Destination IP address
 * @return Pointer to network interface, NULL if no route found
 */
extern struct ip_iface *ip_route_get_iface(ip_addr_t dst);

/* ============================================================================
 * IP Interface Management Functions
 * ============================================================================

/**
 * @brief Allocate and initialize a new IP interface
 * @param addr IP address in string form
 * @param netmask Network mask in string form
 * @return Pointer to allocated IP interface, NULL on failure
 */
extern struct ip_iface *ip_iface_alloc(const char *addr, const char *netmask);

/**
 * @brief Register IP interface with a network device
 * @param dev Network device to associate with interface
 * @param iface IP interface to register
 * @return 0 on success, -1 on failure
 */
extern int ip_iface_register(struct net_device *dev, struct ip_iface *iface);

/**
 * @brief Select IP interface by IP address
 * @param addr IP address to match
 * @return Pointer to IP interface, NULL if not found
 */
extern struct ip_iface *ip_iface_select(ip_addr_t addr);

/* ============================================================================
 * IP Packet Processing Functions
 * ============================================================================

/**
 * @brief Send IP packet
 * @param protocol Upper layer protocol (IP_PROTOCOL_*)
 * @param data Packet payload data
 * @param len Length of payload data
 * @param src Source IP address
 * @param dst Destination IP address
 * @return Number of bytes sent on success, -1 on failure
 */
extern ssize_t ip_output(uint8_t protocol, const uint8_t *data, size_t len,
                        ip_addr_t src, ip_addr_t dst);

/* ============================================================================
 * IP Protocol Handler Registration
 * ============================================================================

/**
 * @brief Register protocol handler for IP packets
 * @param name Protocol name for debugging
 * @param type IP protocol number
 * @param handler Callback function for processing packets
 * @return 0 on success, -1 on failure
 */
extern int ip_protocol_register(const char *name, uint8_t type,
                               void (*handler)(const uint8_t *data, size_t len,
                                              ip_addr_t src, ip_addr_t dst,
                                              struct ip_iface *iface));

/**
 * @brief Get protocol name from protocol number
 * @param type IP protocol number
 * @return Protocol name string, "UNKNOWN" if not registered
 */
extern char *ip_protocol_name(uint8_t type);

/* ============================================================================
 * IP Module Initialization
 * ============================================================================

/**
 * @brief Initialize IP protocol module
 * @return 0 on success, -1 on failure
 */
extern int ip_init(void);

#endif /* IP_H */