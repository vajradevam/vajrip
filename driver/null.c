/**
 * @file null.c
 * @brief Null network device implementation
 * 
 * Provides a virtual null device that silently discards all transmitted packets.
 * Useful for testing and as a placeholder for unused network interfaces.
 */

#include <stdio.h>
#include <stdint.h>

#include "util.h"
#include "net.h"

/* Null device MTU - can handle maximum IP datagram size */
#define NULL_MTU UINT16_MAX

/**
 * @brief Transmit packet on null device (packet sink)
 * @param dev Null device
 * @param type Protocol type
 * @param data Packet data
 * @param len Packet length
 * @param dst Destination address (unused for null device)
 * @return 0 on success
 * 
 * Silently discards all packets without any processing or forwarding.
 * Logs the packet for debugging purposes but takes no further action.
 */
static int null_transmit(struct net_device *dev, uint16_t type,
                        const uint8_t *data, size_t len, const void *dst)
{
    debugf("dev=%s, type=%s(0x%04x), len=%zu", 
           dev->name, net_protocol_name(type), type, len);
    debugdump(data, len);
    
    /* Silently discard all packets (black hole) */
    return 0;
}

/* Null device operations */
static struct net_device_ops null_ops = {
    .transmit = null_transmit,
};

/**
 * @brief Initialize null device parameters
 * @param dev Network device to configure as null device
 */
static void null_setup(struct net_device *dev)
{
    dev->type = NET_DEVICE_TYPE_NULL;
    dev->mtu = NULL_MTU;          /* Maximum IP datagram size */
    dev->hlen = 0;                /* No header for null device */
    dev->alen = 0;                /* No address for null device */
    dev->ops = &null_ops;
}

/**
 * @brief Initialize and register null device
 * @return Pointer to initialized null device, NULL on failure
 */
struct net_device *null_init(void)
{
    struct net_device *dev;

    /* Allocate and setup null device */
    dev = net_device_alloc(null_setup);
    if (!dev) {
        errorf("net_device_alloc() failure");
        return NULL;
    }
    
    /* Register device with network stack */
    if (net_device_register(dev) == -1) {
        errorf("net_device_register() failure");
        return NULL;
    }
    
    debugf("initialized, dev=%s", dev->name);
    return dev;
}