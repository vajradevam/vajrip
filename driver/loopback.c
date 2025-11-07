/**
 * @file loopback.c
 * @brief Loopback network device implementation
 * 
 * Provides a virtual loopback device for local communication testing.
 * Packets sent to this device are immediately looped back to the input handler.
 */

#include <stdio.h>
#include <stdint.h>

#include "util.h"
#include "net.h"
#include "loopback.h"

/* Loopback device MTU - can handle maximum IP datagram size */
#define LOOPBACK_MTU UINT16_MAX

/**
 * @brief Transmit packet on loopback device
 * @param dev Loopback device
 * @param type Protocol type
 * @param data Packet data
 * @param len Packet length
 * @param dst Destination address (unused for loopback)
 * @return 0 on success
 * 
 * Immediately feeds the packet back to the network input handler,
 * simulating reception of the packet from the network.
 */
static int loopback_transmit(struct net_device *dev, uint16_t type,
                            const uint8_t *data, size_t len, const void *dst)
{
    debugf("dev=%s, type=%s(0x%04x), len=%zu", 
           dev->name, net_protocol_name(type), type, len);
    debugdump(data, len);
    
    /* Immediately loop packet back to input handler */
    net_input_handler(type, data, len, dev);
    return 0;
}

/* Loopback device operations */
static struct net_device_ops loopback_ops = {
    .transmit = loopback_transmit,
};

/**
 * @brief Initialize loopback device parameters
 * @param dev Network device to configure as loopback
 */
static void loopback_setup(struct net_device *dev)
{
    dev->type = NET_DEVICE_TYPE_LOOPBACK;
    dev->mtu = LOOPBACK_MTU;      /* Maximum IP datagram size */
    dev->hlen = 0;                /* No header for loopback */
    dev->alen = 0;                /* No address for loopback */
    dev->flags = NET_DEVICE_FLAG_LOOPBACK;
    dev->ops = &loopback_ops;
}

/**
 * @brief Initialize and register loopback device
 * @return Pointer to initialized loopback device, NULL on failure
 */
struct net_device *loopback_init(void)
{
    struct net_device *dev;

    /* Allocate and setup loopback device */
    dev = net_device_alloc(loopback_setup);
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