/**
 * @file ether.c
 * @brief Ethernet protocol implementation
 * 
 * Implements Ethernet frame handling, address conversion, and device management
 * for TCP/IP network stack.
 */

#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>

#include "util.h"
#include "net.h"
#include "ether.h"

/**
 * @brief Ethernet frame header structure
 */
struct ether_hdr {
    uint8_t dst[ETHER_ADDR_LEN];  /* Destination MAC address */
    uint8_t src[ETHER_ADDR_LEN];  /* Source MAC address */
    uint16_t type;                /* Ethernet type (protocol) */
};

/* Special Ethernet address definitions */
const uint8_t ETHER_ADDR_ANY[ETHER_ADDR_LEN] = {"\x00\x00\x00\x00\x00\x00"};
const uint8_t ETHER_ADDR_BROADCAST[ETHER_ADDR_LEN] = {"\xff\xff\xff\xff\xff\xff"};

/**
 * @brief Convert Ethernet address from text to binary format
 * @param p String representation (e.g., "aa:bb:cc:dd:ee:ff")
 * @param n Output buffer for binary address (must be ETHER_ADDR_LEN bytes)
 * @return 0 on success, -1 on failure
 */
int ether_addr_pton(const char *p, uint8_t *n)
{
    int index;
    char *ep;
    long val;

    if (!p || !n) {
        return -1;
    }
    
    /* Parse each byte of the MAC address */
    for (index = 0; index < ETHER_ADDR_LEN; index++) {
        val = strtol(p, &ep, 16);  /* Parse hex byte */
        
        /* Validate parsed value and separators */
        if (ep == p || val < 0 || val > 0xff || 
            (index < ETHER_ADDR_LEN - 1 && *ep != ':')) {
            break;
        }
        
        n[index] = (uint8_t)val;
        p = ep + 1;  /* Move to next byte (skip colon) */
    }
    
    /* Verify we parsed exactly 6 bytes and reached end of string */
    if (index != ETHER_ADDR_LEN || *ep != '\0') {
        return -1;
    }
    
    return 0;
}

/**
 * @brief Convert Ethernet type field to string representation
 * @param type Ethernet type field in network byte order
 * @return String description of the Ethernet type
 */
static const char *ether_type_ntoa(uint16_t type)
{
    switch (ntoh16(type)) {
    case ETHER_TYPE_IP:
        return "IP";
    case ETHER_TYPE_ARP:
        return "ARP";
    case ETHER_TYPE_IPV6:
        return "IPv6";
    }
    return "UNKNOWN";
}

/**
 * @brief Convert Ethernet address from binary to text format
 * @param n Binary MAC address to convert
 * @param p Output buffer for string representation
 * @param size Size of output buffer (should be >= ETHER_ADDR_STR_LEN)
 * @return Pointer to output buffer on success, NULL on failure
 */
char *ether_addr_ntop(const uint8_t *n, char *p, size_t size)
{
    if (!n || !p) {
        return NULL;
    }
    
    /* Format MAC address as colon-separated hex bytes */
    snprintf(p, size, "%02x:%02x:%02x:%02x:%02x:%02x", 
             n[0], n[1], n[2], n[3], n[4], n[5]);
    return p;
}

/**
 * @brief Dump Ethernet frame contents for debugging
 * @param frame Pointer to Ethernet frame data
 * @param flen Length of Ethernet frame
 */
static void ether_dump(const uint8_t *frame, size_t flen)
{
    struct ether_hdr *hdr;
    char addr[ETHER_ADDR_STR_LEN];

    hdr = (struct ether_hdr *)frame;
    
    /* Thread-safe debug output */
    flockfile(stderr);
    fprintf(stderr, "        src: %s\n", 
            ether_addr_ntop(hdr->src, addr, sizeof(addr)));
    fprintf(stderr, "        dst: %s\n", 
            ether_addr_ntop(hdr->dst, addr, sizeof(addr)));
    fprintf(stderr, "       type: 0x%04x (%s)\n", 
            ntoh16(hdr->type), ether_type_ntoa(hdr->type));
#ifdef HEXDUMP
    hexdump(stderr, frame, flen);
#endif
    funlockfile(stderr);
}

/* ============================================================================
 * Ethernet Device Helper Functions
 * ============================================================================

/**
 * @brief Helper function to transmit Ethernet frames
 * @param dev Network device to transmit on
 * @param type Ethernet protocol type
 * @param data Payload data to transmit
 * @param len Length of payload data
 * @param dst Destination MAC address
 * @param callback Device-specific transmit callback
 * @return 0 on success, -1 on failure
 */
int ether_transmit_helper(struct net_device *dev, uint16_t type, 
                         const uint8_t *data, size_t len, const void *dst,
                         ssize_t (*callback)(struct net_device *dev, 
                                           const uint8_t *data, size_t len))
{
    uint8_t frame[ETHER_FRAME_SIZE_MAX] = {};
    struct ether_hdr *hdr;
    size_t flen, pad = 0;

    /* Construct Ethernet header */
    hdr = (struct ether_hdr *)frame;
    memcpy(hdr->dst, dst, ETHER_ADDR_LEN);
    memcpy(hdr->src, dev->addr, ETHER_ADDR_LEN);
    hdr->type = hton16(type);
    
    /* Copy payload data */
    memcpy(hdr + 1, data, len);
    
    /* Add padding if frame is below minimum size */
    if (len < ETHER_PAYLOAD_SIZE_MIN) {
        pad = ETHER_PAYLOAD_SIZE_MIN - len;
    }
    
    /* Calculate total frame length */
    flen = sizeof(*hdr) + len + pad;
    
    debugf("dev=%s, type=%s(0x%04x), len=%zu", 
           dev->name, ether_type_ntoa(hdr->type), type, flen);
    ether_dump(frame, flen);
    
    /* Invoke device-specific transmit callback */
    return callback(dev, frame, flen) == (ssize_t)flen ? 0 : -1;
}

/**
 * @brief Helper function to receive Ethernet frames
 * @param dev Network device to poll
 * @param callback Device-specific receive callback
 * @return 0 on success, -1 on failure
 */
int ether_poll_helper(struct net_device *dev,
                     ssize_t (*callback)(struct net_device *dev, 
                                       uint8_t *buf, size_t size))
{
    uint8_t frame[ETHER_FRAME_SIZE_MAX];
    ssize_t flen;
    struct ether_hdr *hdr;
    uint16_t type;

    /* Receive frame from device */
    flen = callback(dev, frame, sizeof(frame));
    if (flen < (ssize_t)sizeof(*hdr)) {
        errorf("input data is too short");
        return -1;
    }
    
    hdr = (struct ether_hdr *)frame;
    
    /* Filter frames not intended for this device */
    if (memcmp(dev->addr, hdr->dst, ETHER_ADDR_LEN) != 0) {
        if (memcmp(ETHER_ADDR_BROADCAST, hdr->dst, ETHER_ADDR_LEN) != 0) {
            /* Frame is for another host - silently ignore */
            return -1;
        }
    }
    
    /* Extract protocol type and process frame */
    type = ntoh16(hdr->type);
    debugf("dev=%s, type=%s(0x%04x), len=%zu", 
           dev->name, ether_type_ntoa(hdr->type), type, flen);
    ether_dump(frame, flen);
    
    /* Pass payload to appropriate protocol handler */
    return net_input_handler(type, (uint8_t *)(hdr + 1), 
                            flen - sizeof(*hdr), dev);
}

/**
 * @brief Set up Ethernet-specific device parameters
 * @param dev Network device to configure
 */
void ether_setup_helper(struct net_device *dev)
{
    dev->type = NET_DEVICE_TYPE_ETHERNET;
    dev->mtu = ETHER_PAYLOAD_SIZE_MAX;        /* Maximum Transmission Unit */
    dev->flags = (NET_DEVICE_FLAG_BROADCAST | /* Supports broadcast */
                  NET_DEVICE_FLAG_NEED_ARP);  /* Requires ARP resolution */
    dev->hlen = ETHER_HDR_SIZE;               /* Header length */
    dev->alen = ETHER_ADDR_LEN;               /* Address length */
    memcpy(dev->broadcast, ETHER_ADDR_BROADCAST, ETHER_ADDR_LEN);
}