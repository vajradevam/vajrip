/**
 * @file ether.h
 * @brief Ethernet protocol definitions and interfaces
 * 
 * Provides Ethernet frame structure, address handling, and device management
 * for TCP/IP network implementations.
 */

#ifndef ETHER_H
#define ETHER_H

#include <stdio.h>
#include <stdint.h>
#include <unistd.h>
#include <sys/types.h>

#include "net.h"

/* Ethernet address and frame constants */
#define ETHER_ADDR_LEN        6     /* MAC address length in bytes */
#define ETHER_ADDR_STR_LEN    18    /* String representation length: "xx:xx:xx:xx:xx:xx\0" */

/* Ethernet frame size constants */
#define ETHER_HDR_SIZE        14    /* Ethernet header size (without VLAN) */
#define ETHER_FRAME_SIZE_MIN  60    /* Minimum frame size without FCS */
#define ETHER_FRAME_SIZE_MAX  1514  /* Maximum frame size without FCS */

/* Ethernet payload size calculations */
#define ETHER_PAYLOAD_SIZE_MIN (ETHER_FRAME_SIZE_MIN - ETHER_HDR_SIZE)  /* Min payload size */
#define ETHER_PAYLOAD_SIZE_MAX (ETHER_FRAME_SIZE_MAX - ETHER_HDR_SIZE)  /* Max payload size */

/* 
 * Ethernet type fields (protocol identifiers)
 * See: https://www.iana.org/assignments/ieee-802-numbers/ieee-802-numbers.txt
 */
#define ETHER_TYPE_IP         0x0800  /* Internet Protocol version 4 */
#define ETHER_TYPE_ARP        0x0806  /* Address Resolution Protocol */
#define ETHER_TYPE_IPV6       0x86dd  /* Internet Protocol version 6 */

/* Special Ethernet addresses */
extern const uint8_t ETHER_ADDR_ANY[ETHER_ADDR_LEN];           /* Zero address */
extern const uint8_t ETHER_ADDR_BROADCAST[ETHER_ADDR_LEN];     /* Broadcast address */

/**
 * @brief Convert Ethernet address from text to binary form
 * @param p String representation of MAC address (e.g., "aa:bb:cc:dd:ee:ff")
 * @param n Buffer to store binary MAC address (must be ETHER_ADDR_LEN bytes)
 * @return 0 on success, -1 on failure
 */
extern int ether_addr_pton(const char *p, uint8_t *n);

/**
 * @brief Convert Ethernet address from binary to text form
 * @param n Binary MAC address to convert
 * @param p Buffer to store string representation
 * @param size Size of the output buffer (should be at least ETHER_ADDR_STR_LEN)
 * @return Pointer to the string representation, NULL on failure
 */
extern char *ether_addr_ntop(const uint8_t *n, char *p, size_t size);

/**
 * @brief Helper function for transmitting Ethernet frames
 * @param dev Network device to transmit on
 * @param type Ethernet type field (protocol identifier)
 * @param payload Data payload to transmit
 * @param plen Length of payload data
 * @param dst Destination MAC address
 * @param callback Device-specific transmit callback function
 * @return Number of bytes transmitted on success, -1 on failure
 */
extern int ether_transmit_helper(struct net_device *dev, uint16_t type,
                                const uint8_t *payload, size_t plen,
                                const void *dst,
                                ssize_t (*callback)(struct net_device *dev,
                                                   const uint8_t *buf,
                                                   size_t len));

/**
 * @brief Helper function for receiving Ethernet frames
 * @param dev Network device to poll for frames
 * @param callback Device-specific receive callback function
 * @return Number of bytes received on success, -1 on failure
 */
extern int ether_poll_helper(struct net_device *dev,
                            ssize_t (*callback)(struct net_device *dev,
                                               uint8_t *buf, size_t size));

/**
 * @brief Helper function to set up Ethernet device operations
 * @param net_device Network device structure to initialize
 */
extern void ether_setup_helper(struct net_device *net_device);

/**
 * @brief Initialize an Ethernet network device
 * @param name Name of the network device to initialize
 * @return Pointer to initialized network device, NULL on failure
 */
extern struct net_device *ether_init(const char *name);

#endif /* ETHER_H */