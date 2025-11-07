/**
 * @file net.c
 * @brief Core network stack implementation
 * 
 * Implements device management, protocol handling, timer management,
 * and event processing for the TCP/IP network stack.
 */

#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include <sys/time.h>

#include "platform.h"
#include "util.h"
#include "net.h"

/* ============================================================================
 * Internal Data Structures
 * ============================================================================

/**
 * @brief Network protocol handler entry
 */
struct net_protocol {
    struct net_protocol *next;    /* Next protocol in list */
    char name[16];                /* Protocol name */
    uint16_t type;                /* Protocol type */
    struct queue_head queue;      /* Input queue for packet buffering */
    void (*handler)(const uint8_t *data, size_t len, struct net_device *dev);
};

/**
 * @brief Protocol queue entry structure
 * 
 * NOTE: The packet data follows immediately after this structure in memory
 */
struct net_protocol_queue_entry {
    struct net_device *dev;       /* Device that received the packet */
    size_t len;                   /* Length of packet data */
    /* uint8_t data[] follows immediately */
};

/**
 * @brief Network timer entry
 */
struct net_timer {
    struct net_timer *next;       /* Next timer in list */
    char name[16];                /* Timer name */
    struct timeval interval;      /* Timer interval */
    struct timeval last;          /* Last execution time */
    void (*handler)(void);        /* Timer callback function */
};

/**
 * @brief Network event subscription entry
 */
struct net_event {
    struct net_event *next;       /* Next event in list */
    void (*handler)(void *arg);   /* Event callback function */
    void *arg;                    /* Callback argument */
};

/* ============================================================================
 * Global Network State
 * ============================================================================

/* NOTE: if you want to add/delete entries after net_run(), you need to 
   protect these lists with a mutex. */

static struct net_device *devices;     /* List of registered network devices */
static struct net_protocol *protocols; /* List of protocol handlers */
static struct net_timer *timers;       /* List of active timers */
static struct net_event *events;       /* List of event subscribers */

/* ============================================================================
 * Network Device Management
 * ============================================================================

/**
 * @brief Allocate and initialize a new network device
 * @param setup Device-specific setup function
 * @return Pointer to allocated device, NULL on failure
 */
struct net_device *net_device_alloc(void (*setup)(struct net_device *dev))
{
    struct net_device *dev;

    dev = memory_alloc(sizeof(*dev));
    if (!dev) {
        errorf("memory_alloc() failure");
        return NULL;
    }
    
    /* Call device-specific setup if provided */
    if (setup) {
        setup(dev);
    }
    
    return dev;
}

/**
 * @brief Register a network device with the network stack
 * 
 * NOTE: Must not be called after net_run() due to lack of thread safety
 * 
 * @param dev Device to register
 * @return 0 on success, -1 on failure
 */
int net_device_register(struct net_device *dev)
{
    static unsigned int index = 0;

    /* Assign unique index and name */
    dev->index = index++;
    snprintf(dev->name, sizeof(dev->name), "net%d", dev->index);
    
    /* Add to global device list */
    dev->next = devices;
    devices = dev;
    
    infof("registered, dev=%s, type=0x%04x", dev->name, dev->type);
    return 0;
}

/**
 * @brief Open and start a network device
 * @param dev Device to open
 * @return 0 on success, -1 on failure
 */
static int net_device_open(struct net_device *dev)
{
    if (NET_DEVICE_IS_UP(dev)) {
        errorf("already opened, dev=%s", dev->name);
        return -1;
    }
    
    /* Call device-specific open operation */
    if (dev->ops->open) {
        if (dev->ops->open(dev) == -1) {
            errorf("failure, dev=%s", dev->name);
            return -1;
        }
    }
    
    /* Mark device as up and running */
    dev->flags |= NET_DEVICE_FLAG_UP;
    infof("dev=%s, state=%s", dev->name, NET_DEVICE_STATE(dev));
    return 0;
}

/**
 * @brief Close and stop a network device
 * @param dev Device to close
 * @return 0 on success, -1 on failure
 */
static int net_device_close(struct net_device *dev)
{
    if (!NET_DEVICE_IS_UP(dev)) {
        errorf("not opened, dev=%s", dev->name);
        return -1;
    }
    
    /* Call device-specific close operation */
    if (dev->ops->close) {
        if (dev->ops->close(dev) == -1) {
            errorf("failure, dev=%s", dev->name);
            return -1;
        }
    }
    
    /* Mark device as down */
    dev->flags &= ~NET_DEVICE_FLAG_UP;
    infof("dev=%s, state=%s", dev->name, NET_DEVICE_STATE(dev));
    return 0;
}

/**
 * @brief Add a protocol interface to a network device
 * 
 * NOTE: Must not be called after net_run() due to lack of thread safety
 * 
 * @param dev Network device
 * @param iface Protocol interface to add
 * @return 0 on success, -1 on failure
 */
int net_device_add_iface(struct net_device *dev, struct net_iface *iface)
{
    struct net_iface *entry;

    /* Check for duplicate interface family */
    for (entry = dev->ifaces; entry; entry = entry->next) {
        if (entry->family == iface->family) {
            errorf("already exists, dev=%s, family=%d", dev->name, entry->family);
            return -1;
        }
    }
    
    /* Add to device's interface list */
    iface->next = dev->ifaces;
    iface->dev = dev;
    dev->ifaces = iface;
    
    return 0;
}

/**
 * @brief Get protocol interface from device by family type
 * @param dev Network device
 * @param family Protocol family (NET_IFACE_FAMILY_*)
 * @return Pointer to interface, NULL if not found
 */
struct net_iface *net_device_get_iface(struct net_device *dev, int family)
{
    struct net_iface *entry;

    for (entry = dev->ifaces; entry; entry = entry->next) {
        if (entry->family == family) {
            break;
        }
    }
    return entry;
}

/**
 * @brief Output packet through network device
 * @param dev Network device to use for output
 * @param type Protocol type (NET_PROTOCOL_TYPE_*)
 * @param data Packet data to transmit
 * @param len Length of packet data
 * @param dst Destination hardware address
 * @return 0 on success, -1 on failure
 */
int net_device_output(struct net_device *dev, uint16_t type,
                     const uint8_t *data, size_t len, const void *dst)
{
    /* Validate device state */
    if (!NET_DEVICE_IS_UP(dev)) {
        errorf("not opened, dev=%s", dev->name);
        return -1;
    }
    
    /* Validate packet length against MTU */
    if (len > dev->mtu) {
        errorf("too long, dev=%s, mtu=%u, len=%zu", dev->name, dev->mtu, len);
        return -1;
    }
    
    debugf("dev=%s, type=%s(0x%04x), len=%zu", 
           dev->name, net_protocol_name(type), type, len);
    debugdump(data, len);
    
    /* Call device-specific transmit operation */
    if (dev->ops->transmit(dev, type, data, len, dst) == -1) {
        errorf("device transmit failure, dev=%s, len=%zu", dev->name, len);
        return -1;
    }
    
    return 0;
}

/* ============================================================================
 * Protocol Handler Management
 * ============================================================================

/**
 * @brief Main packet input handler for network stack
 * @param type Protocol type of incoming packet
 * @param data Packet data
 * @param len Packet length
 * @param dev Device that received the packet
 * @return 0 on success, -1 on failure
 */
int net_input_handler(uint16_t type, const uint8_t *data, size_t len,
                     struct net_device *dev)
{
    struct net_protocol *proto;
    struct net_protocol_queue_entry *entry;

    /* Find protocol handler for this packet type */
    for (proto = protocols; proto; proto = proto->next) {
        if (proto->type == type) {
            /* Allocate queue entry with space for packet data */
            entry = memory_alloc(sizeof(*entry) + len);
            if (!entry) {
                errorf("memory_alloc() failure");
                return -1;
            }
            
            /* Initialize queue entry */
            entry->dev = dev;
            entry->len = len;
            memcpy(entry + 1, data, len);  /* Copy packet data after entry */
            
            /* Push to protocol's input queue */
            if (!queue_push(&proto->queue, entry)) {
                errorf("queue_push() failure");
                memory_free(entry);
                return -1;
            }
            
            debugf("queue pushed (num:%u), dev=%s, type=%s(0x%04x), len=%zd", 
                   proto->queue.num, dev->name, proto->name, type, len);
            debugdump(data, len);
            
            /* Signal softirq for deferred processing */
            raise_softirq();
            return 0;
        }
    }
    
    /* No handler registered for this protocol - silently ignore */
    return 0;
}

/**
 * @brief Register a protocol handler
 * 
 * NOTE: Must not be called after net_run() due to lack of thread safety
 * 
 * @param name Protocol name for debugging
 * @param type Protocol type (NET_PROTOCOL_TYPE_*)
 * @param handler Function to handle packets of this protocol
 * @return 0 on success, -1 on failure
 */
int net_protocol_register(const char *name, uint16_t type,
                         void (*handler)(const uint8_t *data, size_t len,
                                        struct net_device *dev))
{
    struct net_protocol *proto;

    /* Check for duplicate protocol registration */
    for (proto = protocols; proto; proto = proto->next) {
        if (type == proto->type) {
            errorf("already registered, type=%s(0x%04x), exist=%s(0x%04x)", 
                   name, type, proto->name, proto->type);
            return -1;
        }
    }
    
    /* Allocate and initialize protocol entry */
    proto = memory_alloc(sizeof(*proto));
    if (!proto) {
        errorf("memory_alloc() failure");
        return -1;
    }
    
    strncpy(proto->name, name, sizeof(proto->name)-1);
    proto->type = type;
    proto->handler = handler;
    proto->next = protocols;
    protocols = proto;
    
    infof("registered, type=%s(0x%04x)", proto->name, type);
    return 0;
}

/**
 * @brief Get protocol name from protocol type
 * @param type Protocol type
 * @return Protocol name string, "UNKNOWN" if not registered
 */
char *net_protocol_name(uint16_t type)
{
    struct net_protocol *entry;

    for (entry = protocols; entry; entry = entry->next) {
        if (entry->type == type) {
            return entry->name;
        }
    }
    return "UNKNOWN";
}

/**
 * @brief Process pending protocol packets
 * @return 0 on success, -1 on error
 */
int net_protocol_handler(void)
{
    struct net_protocol *proto;
    struct net_protocol_queue_entry *entry;
    unsigned int num;

    /* Process all protocols */
    for (proto = protocols; proto; proto = proto->next) {
        /* Process all queued packets for this protocol */
        while (1) {
            entry = queue_pop(&proto->queue);
            if (!entry) {
                break;  /* No more packets in queue */
            }
            
            num = proto->queue.num;
            debugf("queue popped (num:%u), dev=%s, type=0x%04x, len=%zd", 
                   num, entry->dev->name, proto->type, entry->len);
            debugdump((uint8_t *)(entry + 1), entry->len);
            
            /* Call protocol handler with packet data */
            proto->handler((uint8_t *)(entry + 1), entry->len, entry->dev);
            
            /* Free queue entry (includes packet data) */
            free(entry);
        }
    }
    return 0;
}

/* ============================================================================
 * Timer Management
 * ============================================================================

/**
 * @brief Register a timer handler
 * 
 * NOTE: Must not be called after net_run() due to lack of thread safety
 * 
 * @param name Timer name for debugging
 * @param interval Timer interval
 * @param handler Function to call on timer expiration
 * @return 0 on success, -1 on failure
 */
int net_timer_register(const char *name, struct timeval interval,
                      void (*handler)(void))
{
    struct net_timer *timer;

    timer = memory_alloc(sizeof(*timer));
    if (!timer) {
        errorf("memory_alloc() failure");
        return -1;
    }
    
    strncpy(timer->name, name, sizeof(timer->name)-1);
    timer->interval = interval;
    gettimeofday(&timer->last, NULL);
    timer->handler = handler;
    timer->next = timers;
    timers = timer;
    
    infof("registered: %s interval={%ld, %ld}", 
          timer->name, interval.tv_sec, interval.tv_usec);
    return 0;
}

/**
 * @brief Process expired timers
 * @return 0 on success, -1 on error
 */
int net_timer_handler(void)
{
    struct net_timer *timer;
    struct timeval now, diff;

    for (timer = timers; timer; timer = timer->next) {
        gettimeofday(&now, NULL);
        timersub(&now, &timer->last, &diff);
        
        /* Check if timer interval has elapsed */
        if (timercmp(&timer->interval, &diff, <) != 0) {
            /* Execute timer handler and update last execution time */
            timer->handler();
            timer->last = now;
        }
    }
    return 0;
}

/* ============================================================================
 * Interrupt and Event Handling
 * ============================================================================

/**
 * @brief Signal network interrupt (for device drivers)
 * 
 * Uses SIGUSR2 to signal the main process that network activity occurred.
 * getpid(2) and kill(2) are signal safety functions (see signal-safety(7)).
 * 
 * @return 0 on success, -1 on failure
 */
int net_interrupt(void)
{
    return kill(getpid(), SIGUSR2);
}

/**
 * @brief Subscribe to network events
 * 
 * NOTE: Must not be called after net_run() due to lack of thread safety
 * 
 * @param handler Function to call when event occurs
 * @param arg Argument to pass to handler
 * @return 0 on success, -1 on failure
 */
int net_event_subscribe(void (*handler)(void *arg), void *arg)
{
    struct net_event *event;

    event = memory_alloc(sizeof(*event));
    if (!event) {
        errorf("memory_alloc() failure");
        return -1;
    }
    
    event->handler = handler;
    event->arg = arg;
    event->next = events;
    events = event;
    
    return 0;
}

/**
 * @brief Process pending network events
 * @return 0 on success, -1 on error
 */
int net_event_handler(void)
{
    struct net_event *event;

    for (event = events; event; event = event->next) {
        event->handler(event->arg);
    }
    return 0;
}

/* ============================================================================
 * Network Stack Control Functions
 * ============================================================================

/**
 * @brief Start the network stack main loop
 * @return 0 on success, -1 on failure
 */
int net_run(void)
{
    struct net_device *dev;

    /* Initialize interrupt handling */
    if (intr_run() == -1) {
        errorf("intr_run() failure");
        return -1;
    }
    
    /* Open all registered network devices */
    debugf("open all devices...");
    for (dev = devices; dev; dev = dev->next) {
        net_device_open(dev);
    }
    
    debugf("running...");
    return 0;
}

/**
 * @brief Shutdown the network stack gracefully
 */
void net_shutdown(void)
{
    struct net_device *dev;

    /* Close all network devices */
    debugf("close all devices...");
    for (dev = devices; dev; dev = dev->next) {
        net_device_close(dev);
    }
    
    debugf("shutdown");
}

/* ============================================================================
 * Network Stack Initialization
 * ============================================================================

/* Protocol module headers */
#include "arp.h"
#include "ip.h"
#include "icmp.h"
#include "udp.h"
#include "tcp.h"

/**
 * @brief Initialize the network stack and all protocol modules
 * @return 0 on success, -1 on failure
 */
int net_init(void)
{
    /* Initialize interrupt subsystem */
    if (intr_init() == -1) {
        errorf("intr_init() failure");
        return -1;
    }
    
    /* Initialize protocol modules in dependency order */
    if (arp_init() == -1) {
        errorf("arp_init() failure");
        return -1;
    }
    if (ip_init() == -1) {
        errorf("ip_init() failure");
        return -1;
    }
    if (icmp_init() == -1) {
        errorf("icmp_init() failure");
        return -1;
    }
    if (udp_init() == -1) {
        errorf("udp_init() failure");
        return -1;
    }
    if (tcp_init() == -1) {
        errorf("tcp_init() failure");
        return -1;
    }
    
    infof("initialized");
    return 0;
}