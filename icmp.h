/**
 * @file icmp.h
 * @brief ICMP (Internet Control Message Protocol) definitions and interfaces
 * 
 * Provides ICMP protocol functionality for network diagnostics, error reporting,
 * and control messages in TCP/IP implementations.
 */

#ifndef ICMP_H
#define ICMP_H

#include <stddef.h>
#include <stdint.h>

#include "ip.h"

/* ICMP header size in bytes */
#define ICMP_HDR_SIZE 8

/* 
 * ICMP Message Type Definitions
 * Used to identify the purpose of ICMP messages
 */
#define ICMP_TYPE_ECHOREPLY           0   /* Echo Reply */
#define ICMP_TYPE_DEST_UNREACH        3   /* Destination Unreachable */
#define ICMP_TYPE_SOURCE_QUENCH       4   /* Source Quench (congestion control) */
#define ICMP_TYPE_REDIRECT            5   /* Redirect Message */
#define ICMP_TYPE_ECHO                8   /* Echo Request */
#define ICMP_TYPE_TIME_EXCEEDED      11   /* Time Exceeded */
#define ICMP_TYPE_PARAM_PROBLEM      12   /* Parameter Problem */
#define ICMP_TYPE_TIMESTAMP          13   /* Timestamp Request */
#define ICMP_TYPE_TIMESTAMPREPLY     14   /* Timestamp Reply */
#define ICMP_TYPE_INFO_REQUEST       15   /* Information Request */
#define ICMP_TYPE_INFO_REPLY         16   /* Information Reply */

/* 
 * Destination Unreachable Codes (for ICMP_TYPE_DEST_UNREACH)
 * Specify why a destination could not be reached
 */
#define ICMP_CODE_NET_UNREACH         0   /* Network unreachable */
#define ICMP_CODE_HOST_UNREACH        1   /* Host unreachable */
#define ICMP_CODE_PROTO_UNREACH       2   /* Protocol unreachable */
#define ICMP_CODE_PORT_UNREACH        3   /* Port unreachable */
#define ICMP_CODE_FRAGMENT_NEEDED     4   /* Fragmentation needed but DF set */
#define ICMP_CODE_SOURCE_ROUTE_FAILED 5   /* Source route failed */

/* 
 * Redirect Message Codes (for ICMP_TYPE_REDIRECT)
 * Specify the type of redirect
 */
#define ICMP_CODE_REDIRECT_NET        0   /* Redirect for the Network */
#define ICMP_CODE_REDIRECT_HOST       1   /* Redirect for the Host */
#define ICMP_CODE_REDIRECT_TOS_NET    2   /* Redirect for Type of Service and Network */
#define ICMP_CODE_REDIRECT_TOS_HOST   3   /* Redirect for Type of Service and Host */

/* 
 * Time Exceeded Codes (for ICMP_TYPE_TIME_EXCEEDED)
 * Specify why a packet's time was exceeded
 */
#define ICMP_CODE_EXCEEDED_TTL        0   /* Time to Live exceeded in transit */
#define ICMP_CODE_EXCEEDED_FRAGMENT   1   /* Fragment reassembly time exceeded */

/**
 * @brief Send an ICMP message
 * 
 * Constructs and sends an ICMP message with the specified parameters.
 * Used for error reporting, diagnostics, and control messages.
 *
 * @param type ICMP message type (ICMP_TYPE_*)
 * @param code ICMP message code (ICMP_CODE_* for the given type)
 * @param values Additional values (depends on message type):
 *               - For redirect: gateway IP address
 *               - For parameter problem: pointer to error
 *               - For timestamp: timestamp values
 * @param data Pointer to ICMP message payload data
 * @param len Length of payload data in bytes
 * @param src Source IP address for the ICMP packet
 * @param dst Destination IP address for the ICMP packet
 * @return 0 on success, -1 on failure
 */
extern int icmp_output(uint8_t type, uint8_t code, uint32_t values,
                      const uint8_t *data, size_t len, 
                      ip_addr_t src, ip_addr_t dst);

/**
 * @brief Initialize the ICMP protocol module
 * 
 * Registers the ICMP protocol handler with the IP layer.
 *
 * @return 0 on success, -1 on failure
 */
extern int icmp_init(void);

#endif /* ICMP_H */