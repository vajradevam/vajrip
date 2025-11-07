/**
 * @file arp.h
 * @brief ARP (Address Resolution Protocol) definitions and interfaces
 * 
 * Provides ARP protocol functionality for mapping IP addresses to MAC addresses
 * in TCP/IP network implementations.
 */

#ifndef ARP_H
#define ARP_H

#include <stdint.h>
#include "net.h"
#include "ip.h"

/* ARP resolution result codes */
#define ARP_RESOLVE_FOUND       0  /* Resolution successful */
#define ARP_RESOLVE_INCOMPLETE  1  /* Resolution in progress */
#define ARP_RESOLVE_ERROR      -1  /* Resolution failed */

/**
 * @brief Initialize the ARP protocol module
 * @return 0 on success, -1 on failure
 */
int arp_init(void);

/**
 * @brief Resolve an IP address to a MAC address
 * @param iface Network interface to use for resolution
 * @param pa IP address to resolve
 * @param ha Buffer to store resulting MAC address (must be ETHER_ADDR_LEN bytes)
 * @return Resolution status code (ARP_RESOLVE_*)
 */
int arp_resolve(struct net_iface *iface, ip_addr_t pa, uint8_t *ha);

#endif /* ARP_H */