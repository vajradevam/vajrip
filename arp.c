/**
 * @file arp.c
 * @brief ARP (Address Resolution Protocol) implementation
 * 
 * Implements ARP cache management, request/reply handling, and IP-to-MAC
 * address resolution for Ethernet networks.
 */

#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <sys/time.h>

#include "platform.h"
#include "util.h"
#include "net.h"
#include "ether.h"
#include "arp.h"
#include "ip.h"

/* IANA ARP parameters - see https://www.iana.org/assignments/arp-parameters/ */
#define ARP_HRD_ETHER    0x0001  /* Ethernet hardware type */
#define ARP_PRO_IP       ETHER_TYPE_IP  /* IP protocol type (matches Ethernet) */

/* ARP operation codes */
#define ARP_OP_REQUEST   0x0001  /* ARP request operation */
#define ARP_OP_REPLY     0x0002  /* ARP reply operation */

/* ARP cache configuration */
#define ARP_CACHE_SIZE       32     /* Maximum cache entries */
#define ARP_CACHE_TIMEOUT    30     /* Cache entry timeout in seconds */

/* ARP cache entry states */
#define ARP_CACHE_STATE_FREE         0  /* Entry is unused */
#define ARP_CACHE_STATE_INCOMPLETE   1  /* Resolution in progress */
#define ARP_CACHE_STATE_RESOLVED     2  /* Resolution successful */
#define ARP_CACHE_STATE_STATIC       3  /* Static entry (never expires) */

/**
 * @brief ARP message header structure
 */
struct arp_hdr {
    uint16_t hrd;   /* Hardware address space */
    uint16_t pro;   /* Protocol address space */
    uint8_t  hln;   /* Hardware address length */
    uint8_t  pln;   /* Protocol address length */
    uint16_t op;    /* Operation code */
};

/**
 * @brief Ethernet-specific ARP message structure
 */
struct arp_ether {
    struct arp_hdr hdr;         /* ARP header */
    uint8_t sha[ETHER_ADDR_LEN]; /* Sender hardware address */
    uint8_t spa[IP_ADDR_LEN];   /* Sender protocol address */
    uint8_t tha[ETHER_ADDR_LEN]; /* Target hardware address */
    uint8_t tpa[IP_ADDR_LEN];   /* Target protocol address */
};

/**
 * @brief ARP cache entry structure
 */
struct arp_cache {
    unsigned char state;        /* Entry state (ARP_CACHE_STATE_*) */
    ip_addr_t pa;               /* Protocol (IP) address */
    uint8_t ha[ETHER_ADDR_LEN]; /* Hardware (MAC) address */
    struct timeval timestamp;   /* Last update time */
};

/* Module global variables */
static mutex_t mutex = MUTEX_INITIALIZER;           /* Cache access mutex */
static struct arp_cache caches[ARP_CACHE_SIZE];     /* ARP cache storage */

/**
 * @brief Convert ARP opcode to string representation
 * @param opcode ARP operation code in network byte order
 * @return String description of the opcode
 */
static char *arp_opcode_ntoa(uint16_t opcode)
{
    switch (ntoh16(opcode)) {
    case ARP_OP_REQUEST:
        return "Request";
    case ARP_OP_REPLY:
        return "Reply";
    }
    return "Unknown";
}

/**
 * @brief Dump ARP packet contents for debugging
 * @param data Pointer to ARP packet data
 * @param len Length of ARP packet data
 */
static void arp_dump(const uint8_t *data, size_t len)
{
    struct arp_ether *message;
    ip_addr_t spa, tpa;
    char addr[128];

    message = (struct arp_ether *)data;
    
    flockfile(stderr);
    fprintf(stderr, "        hrd: 0x%04x\n", ntoh16(message->hdr.hrd));
    fprintf(stderr, "        pro: 0x%04x\n", ntoh16(message->hdr.pro));
    fprintf(stderr, "        hln: %u\n", message->hdr.hln);
    fprintf(stderr, "        pln: %u\n", message->hdr.pln);
    fprintf(stderr, "         op: 0x%04x (%s)\n", ntoh16(message->hdr.op), 
            arp_opcode_ntoa(message->hdr.op));
    fprintf(stderr, "        sha: %s\n", 
            ether_addr_ntop(message->sha, addr, sizeof(addr)));
    memcpy(&spa, message->spa, sizeof(spa));
    fprintf(stderr, "        spa: %s\n", 
            ip_addr_ntop(spa, addr, sizeof(addr)));
    fprintf(stderr, "        tha: %s\n", 
            ether_addr_ntop(message->tha, addr, sizeof(addr)));
    memcpy(&tpa, message->tpa, sizeof(tpa));
    fprintf(stderr, "        tpa: %s\n", 
            ip_addr_ntop(tpa, addr, sizeof(addr)));
#ifdef HEXDUMP
    hexdump(stderr, data, len);
#endif
    funlockfile(stderr);
}

/* ============================================================================
 * ARP Cache Management Functions
 * 
 * NOTE: These functions must be called with mutex locked
 * ============================================================================

/**
 * @brief Allocate a new cache entry, evicting oldest if necessary
 * @return Pointer to allocated cache entry, NULL if no space available
 */
static struct arp_cache *arp_cache_alloc(void)
{
    struct arp_cache *entry, *oldest = NULL;

    /* First try to find a free entry */
    for (entry = caches; entry < tailof(caches); entry++) {
        if (entry->state == ARP_CACHE_STATE_FREE) {
            return entry;
        }
        /* Track oldest entry for eviction if needed */
        if (!oldest || timercmp(&oldest->timestamp, &entry->timestamp, >)) {
            oldest = entry;
        }
    }
    
    /* No free entries, evict the oldest */
    return oldest;
}

/**
 * @brief Find cache entry for given protocol address
 * @param pa Protocol (IP) address to search for
 * @return Pointer to cache entry, NULL if not found
 */
static struct arp_cache *arp_cache_select(ip_addr_t pa)
{
    struct arp_cache *entry;

    for (entry = caches; entry < tailof(caches); entry++) {
        if (entry->state != ARP_CACHE_STATE_FREE && entry->pa == pa) {
            return entry;
        }
    }
    return NULL;
}

/**
 * @brief Update existing cache entry with new hardware address
 * @param pa Protocol address of entry to update
 * @param ha New hardware address
 * @return Pointer to updated cache entry, NULL if not found
 */
static struct arp_cache *arp_cache_update(ip_addr_t pa, const uint8_t *ha)
{
    struct arp_cache *cache;
    char addr1[IP_ADDR_STR_LEN];
    char addr2[ETHER_ADDR_STR_LEN];

    cache = arp_cache_select(pa);
    if (!cache) {
        return NULL; /* Entry not found */
    }
    
    cache->state = ARP_CACHE_STATE_RESOLVED;
    memcpy(cache->ha, ha, ETHER_ADDR_LEN);
    gettimeofday(&cache->timestamp, NULL);
    
    debugf("UPDATE: pa=%s, ha=%s", 
           ip_addr_ntop(pa, addr1, sizeof(addr1)), 
           ether_addr_ntop(ha, addr2, sizeof(addr2)));
    return cache;
}

/**
 * @brief Insert a new cache entry
 * @param pa Protocol address for new entry
 * @param ha Hardware address for new entry
 * @return Pointer to new cache entry, NULL on failure
 */
static struct arp_cache *arp_cache_insert(ip_addr_t pa, const uint8_t *ha)
{
    struct arp_cache *cache;
    char addr1[IP_ADDR_STR_LEN];
    char addr2[ETHER_ADDR_STR_LEN];

    cache = arp_cache_alloc();
    if (!cache) {
        errorf("arp_cache_alloc() failure");
        return NULL;
    }
    
    cache->state = ARP_CACHE_STATE_RESOLVED;
    cache->pa = pa;
    memcpy(cache->ha, ha, ETHER_ADDR_LEN);
    gettimeofday(&cache->timestamp, NULL);
    
    debugf("INSERT: pa=%s, ha=%s", 
           ip_addr_ntop(pa, addr1, sizeof(addr1)), 
           ether_addr_ntop(ha, addr2, sizeof(addr2)));
    return cache;
}

/**
 * @brief Delete a cache entry
 * @param cache Pointer to cache entry to delete
 */
static void arp_cache_delete(struct arp_cache *cache)
{
    char addr1[IP_ADDR_STR_LEN];
    char addr2[ETHER_ADDR_STR_LEN];

    debugf("DELETE: pa=%s, ha=%s", 
           ip_addr_ntop(cache->pa, addr1, sizeof(addr1)), 
           ether_addr_ntop(cache->ha, addr2, sizeof(addr2)));
    
    cache->state = ARP_CACHE_STATE_FREE;
    cache->pa = 0;
    memset(cache->ha, 0, ETHER_ADDR_LEN);
    timerclear(&cache->timestamp);
}

/* ============================================================================
 * ARP Packet Handling Functions
 * ============================================================================

/**
 * @brief Send an ARP request for the given target protocol address
 * @param iface Network interface to send request on
 * @param tpa Target protocol address to resolve
 * @return 0 on success, -1 on failure
 */
static int arp_request(struct net_iface *iface, ip_addr_t tpa)
{
    struct arp_ether request;

    /* Build ARP request packet */
    request.hdr.hrd = hton16(ARP_HRD_ETHER);
    request.hdr.pro = hton16(ARP_PRO_IP);
    request.hdr.hln = ETHER_ADDR_LEN;
    request.hdr.pln = IP_ADDR_LEN;
    request.hdr.op = hton16(ARP_OP_REQUEST);
    memcpy(request.sha, iface->dev->addr, ETHER_ADDR_LEN);
    memcpy(request.spa, &((struct ip_iface *)iface)->unicast, IP_ADDR_LEN);
    memset(request.tha, 0, ETHER_ADDR_LEN);
    memcpy(request.tpa, &tpa, IP_ADDR_LEN);
    
    debugf("dev=%s, opcode=%s(0x%04x), len=%zu", 
           iface->dev->name, arp_opcode_ntoa(request.hdr.op), 
           ntoh16(request.hdr.op), sizeof(request));
    arp_dump((uint8_t *)&request, sizeof(request));
    
    /* Broadcast the ARP request */
    return net_device_output(iface->dev, ETHER_TYPE_ARP, 
                            (uint8_t *)&request, sizeof(request), 
                            iface->dev->broadcast);
}

/**
 * @brief Send an ARP reply to a specific host
 * @param iface Network interface to send reply from
 * @param tha Target hardware address (destination MAC)
 * @param tpa Target protocol address (destination IP)
 * @param dst Destination MAC address for Ethernet frame
 * @return 0 on success, -1 on failure
 */
static int arp_reply(struct net_iface *iface, const uint8_t *tha, 
                     ip_addr_t tpa, const uint8_t *dst)
{
    struct arp_ether reply;

    /* Build ARP reply packet */
    reply.hdr.hrd = hton16(ARP_HRD_ETHER);
    reply.hdr.pro = hton16(ARP_PRO_IP);
    reply.hdr.hln = ETHER_ADDR_LEN;
    reply.hdr.pln = IP_ADDR_LEN;
    reply.hdr.op = hton16(ARP_OP_REPLY);
    memcpy(reply.sha, iface->dev->addr, ETHER_ADDR_LEN);
    memcpy(reply.spa, &((struct ip_iface *)iface)->unicast, IP_ADDR_LEN);
    memcpy(reply.tha, tha, ETHER_ADDR_LEN);
    memcpy(reply.tpa, &tpa, IP_ADDR_LEN);
    
    debugf("dev=%s, opcode=%s(0x%04x), len=%zu", 
           iface->dev->name, arp_opcode_ntoa(reply.hdr.op), 
           ntoh16(reply.hdr.op), sizeof(reply));
    arp_dump((uint8_t *)&reply, sizeof(reply));
    
    /* Send ARP reply directly to requesting host */
    return net_device_output(iface->dev, ETHER_TYPE_ARP, 
                            (uint8_t *)&reply, sizeof(reply), dst);
}

/**
 * @brief Process incoming ARP packets
 * @param data Pointer to ARP packet data
 * @param len Length of ARP packet data
 * @param dev Network device that received the packet
 */
static void arp_input(const uint8_t *data, size_t len, struct net_device *dev)
{
    struct arp_ether *msg;
    ip_addr_t spa, tpa;
    int merge = 0;
    struct net_iface *iface;

    /* Validate packet length */
    if (len < sizeof(*msg)) {
        errorf("too short");
        return;
    }
    
    msg = (struct arp_ether *)data;
    
    /* Validate hardware type and address length */
    if (ntoh16(msg->hdr.hrd) != ARP_HRD_ETHER || msg->hdr.hln != ETHER_ADDR_LEN) {
        errorf("unsupported hardware address");
        return;
    }
    
    /* Validate protocol type and address length */
    if (ntoh16(msg->hdr.pro) != ARP_PRO_IP || msg->hdr.pln != IP_ADDR_LEN) {
        errorf("unsupported protocol address");
        return;
    }
    
    debugf("dev=%s, opcode=%s(0x%04x), len=%zu", 
           dev->name, arp_opcode_ntoa(msg->hdr.op), ntoh16(msg->hdr.op), len);
    arp_dump(data, len);
    
    /* Extract addresses from ARP message */
    memcpy(&spa, msg->spa, sizeof(spa));
    memcpy(&tpa, msg->tpa, sizeof(tpa));
    
    /* Update cache with sender's information */
    mutex_lock(&mutex);
    if (arp_cache_update(spa, msg->sha)) {
        merge = 1; /* Entry was updated */
    }
    mutex_unlock(&mutex);
    
    /* Check if this ARP packet is for our interface */
    iface = net_device_get_iface(dev, NET_IFACE_FAMILY_IP);
    if (iface && ((struct ip_iface *)iface)->unicast == tpa) {
        /* If not merged, insert new cache entry */
        if (!merge) {
            mutex_lock(&mutex);
            arp_cache_insert(spa, msg->sha);
            mutex_unlock(&mutex);
        }
        
        /* If this is an ARP request for our address, send reply */
        if (ntoh16(msg->hdr.op) == ARP_OP_REQUEST) {
            arp_reply(iface, msg->sha, spa, msg->sha);
        }
    }
}

/* ============================================================================
 * Public ARP Interface Functions
 * ============================================================================

/**
 * @brief Resolve an IP address to MAC address using ARP
 * @param iface Network interface to use for resolution
 * @param pa IP address to resolve
 * @param ha Buffer to store resulting MAC address
 * @return Resolution status (ARP_RESOLVE_*)
 */
int arp_resolve(struct net_iface *iface, ip_addr_t pa, uint8_t *ha)
{
    struct arp_cache *cache;
    char addr1[IP_ADDR_STR_LEN];
    char addr2[ETHER_ADDR_STR_LEN];

    /* Validate interface type */
    if (iface->dev->type != NET_DEVICE_TYPE_ETHERNET) {
        debugf("unsupported hardware address type");
        return ARP_RESOLVE_ERROR;
    }
    
    /* Validate protocol family */
    if (iface->family != NET_IFACE_FAMILY_IP) {
        debugf("unsupported protocol address type");
        return ARP_RESOLVE_ERROR;
    }
    
    mutex_lock(&mutex);
    
    /* Look for existing cache entry */
    cache = arp_cache_select(pa);
    if (!cache) {
        /* No entry found, create new incomplete entry and send request */
        cache = arp_cache_alloc();
        if (!cache) {
            mutex_unlock(&mutex);
            errorf("arp_cache_alloc() failure");
            return ARP_RESOLVE_ERROR;
        }
        
        cache->state = ARP_CACHE_STATE_INCOMPLETE;
        cache->pa = pa;
        gettimeofday(&cache->timestamp, NULL);
        arp_request(iface, pa);
        
        mutex_unlock(&mutex);
        debugf("cache not found, pa=%s", ip_addr_ntop(pa, addr1, sizeof(addr1)));
        return ARP_RESOLVE_INCOMPLETE;
    }
    
    /* Handle incomplete resolution */
    if (cache->state == ARP_CACHE_STATE_INCOMPLETE) {
        arp_request(iface, pa); /* Retransmit in case of packet loss */
        mutex_unlock(&mutex);
        return ARP_RESOLVE_INCOMPLETE;
    }
    
    /* Return resolved hardware address */
    memcpy(ha, cache->ha, ETHER_ADDR_LEN);
    mutex_unlock(&mutex);
    
    debugf("resolved, pa=%s, ha=%s",
           ip_addr_ntop(pa, addr1, sizeof(addr1)), 
           ether_addr_ntop(ha, addr2, sizeof(addr2)));
    return ARP_RESOLVE_FOUND;
}

/**
 * @brief ARP cache maintenance timer function
 * 
 * Periodically cleans up expired cache entries
 */
static void arp_timer(void)
{
    struct arp_cache *entry;
    struct timeval now, diff;

    mutex_lock(&mutex);
    gettimeofday(&now, NULL);
    
    /* Check all cache entries for expiration */
    for (entry = caches; entry < tailof(caches); entry++) {
        if (entry->state != ARP_CACHE_STATE_FREE && 
            entry->state != ARP_CACHE_STATE_STATIC) {
            
            timersub(&now, &entry->timestamp, &diff);
            if (diff.tv_sec > ARP_CACHE_TIMEOUT) {
                arp_cache_delete(entry);
            }
        }
    }
    mutex_unlock(&mutex);
}

/**
 * @brief Initialize the ARP protocol module
 * @return 0 on success, -1 on failure
 */
int arp_init(void)
{
    struct timeval interval = {1, 0}; /* 1-second timer interval */

    /* Register ARP protocol handler */
    if (net_protocol_register("ARP", NET_PROTOCOL_TYPE_ARP, arp_input) == -1) {
        errorf("net_protocol_register() failure");
        return -1;
    }
    
    /* Register ARP cache maintenance timer */
    if (net_timer_register("ARP Timer", interval, arp_timer) == -1) {
        errorf("net_timer_register() failure");
        return -1;
    }
    
    return 0;
}