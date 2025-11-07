/**
 * @file udp.c
 * @brief UDP protocol implementation
 * 
 * Implements User Datagram Protocol for connectionless, unreliable datagram
 * communication with socket-like interface support.
 */

#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <errno.h>

#include "platform.h"
#include "util.h"
#include "net.h"
#include "ip.h"
#include "udp.h"

/* UDP configuration constants */
#define UDP_PCB_SIZE 16           /* Maximum number of UDP sockets */

/* UDP PCB state definitions */
#define UDP_PCB_STATE_FREE    0   /* PCB is unused */
#define UDP_PCB_STATE_OPEN    1   /* PCB is active and open */
#define UDP_PCB_STATE_CLOSING 2   /* PCB is being closed */

/* Dynamic port allocation range (RFC 6335) */
#define UDP_SOURCE_PORT_MIN 49152 /* Start of ephemeral port range */
#define UDP_SOURCE_PORT_MAX 65535 /* End of ephemeral port range */

/**
 * @brief Pseudo header for UDP checksum calculation
 */
struct pseudo_hdr {
    uint32_t src;      /* Source IP address */
    uint32_t dst;      /* Destination IP address */
    uint8_t zero;      /* Zero padding */
    uint8_t protocol;  /* Protocol number (UDP) */
    uint16_t len;      /* UDP length */
};

/**
 * @brief UDP header structure
 */
struct udp_hdr {
    uint16_t src;    /* Source port */
    uint16_t dst;    /* Destination port */
    uint16_t len;    /* UDP header and data length */
    uint16_t sum;    /* Checksum */
};

/**
 * @brief UDP Protocol Control Block (PCB)
 * 
 * Manages state for a single UDP socket endpoint.
 */
struct udp_pcb {
    int state;                   /* PCB state (UDP_PCB_STATE_*) */
    struct ip_endpoint local;    /* Local endpoint (address and port) */
    struct queue_head queue;     /* Receive queue for incoming datagrams */
    struct sched_ctx ctx;        /* Scheduling context for blocking operations */
};

/**
 * @brief UDP receive queue entry
 * 
 * NOTE: The datagram data follows immediately after this structure in memory
 */
struct udp_queue_entry {
    struct ip_endpoint foreign;  /* Source endpoint of received datagram */
    uint16_t len;                /* Length of datagram data */
    /* uint8_t data[] follows immediately */
};

/* Global UDP state */
static mutex_t mutex = MUTEX_INITIALIZER;  /* PCB access mutex */
static struct udp_pcb pcbs[UDP_PCB_SIZE];   /* PCB table */

/**
 * @brief Dump UDP packet for debugging
 * @param data UDP packet data
 * @param len Packet length
 */
static void udp_dump(const uint8_t *data, size_t len)
{
    struct udp_hdr *hdr;

    flockfile(stderr);
    hdr = (struct udp_hdr *)data;
    fprintf(stderr, "        src: %u\n", ntoh16(hdr->src));
    fprintf(stderr, "        dst: %u\n", ntoh16(hdr->dst));
    fprintf(stderr, "        len: %u\n", ntoh16(hdr->len));
    fprintf(stderr, "        sum: 0x%04x\n", ntoh16(hdr->sum));
#ifdef HEXDUMP
    hexdump(stderr, data, len);
#endif
    funlockfile(stderr);
}

/* ============================================================================
 * UDP Protocol Control Block (PCB) Management
 * 
 * NOTE: PCB functions must be called with mutex locked
 * ============================================================================

/**
 * @brief Allocate a new UDP PCB
 * @return Pointer to allocated PCB, NULL if no free PCBs
 */
static struct udp_pcb *udp_pcb_alloc(void)
{
    struct udp_pcb *pcb;

    for (pcb = pcbs; pcb < tailof(pcbs); pcb++) {
        if (pcb->state == UDP_PCB_STATE_FREE) {
            pcb->state = UDP_PCB_STATE_OPEN;
            sched_ctx_init(&pcb->ctx);
            return pcb;
        }
    }
    return NULL;
}

/**
 * @brief Release a UDP PCB and cleanup resources
 * @param pcb PCB to release
 */
static void udp_pcb_release(struct udp_pcb *pcb)
{
    struct queue_entry *entry;

    pcb->state = UDP_PCB_STATE_CLOSING;
    
    /* Destroy scheduling context */
    if (sched_ctx_destroy(&pcb->ctx) == -1) {
        sched_wakeup(&pcb->ctx);
        return;
    }
    
    /* Reset PCB state */
    pcb->state = UDP_PCB_STATE_FREE;
    pcb->local.addr = IP_ADDR_ANY;
    pcb->local.port = 0;
    
    /* Cleanup receive queue */
    while ((entry = queue_pop(&pcb->queue)) != NULL) {
        memory_free(entry);
    }
}

/**
 * @brief Select PCB matching local address and port
 * @param addr Local IP address
 * @param port Local port number
 * @return Matching PCB, NULL if not found
 */
static struct udp_pcb *udp_pcb_select(ip_addr_t addr, uint16_t port)
{
    struct udp_pcb *pcb;

    for (pcb = pcbs; pcb < tailof(pcbs); pcb++) {
        if (pcb->state == UDP_PCB_STATE_OPEN) {
            if ((pcb->local.addr == IP_ADDR_ANY || pcb->local.addr == addr) && 
                pcb->local.port == port) {
                return pcb;
            }
        }
    }
    return NULL;
}

/**
 * @brief Get PCB by ID
 * @param id PCB ID
 * @return PCB pointer, NULL if invalid ID
 */
static struct udp_pcb *udp_pcb_get(int id)
{
    struct udp_pcb *pcb;

    if (id < 0 || id >= (int)countof(pcbs)) {
        return NULL;
    }
    pcb = &pcbs[id];
    if (pcb->state != UDP_PCB_STATE_OPEN) {
        return NULL;
    }
    return pcb;
}

/**
 * @brief Get PCB ID
 * @param pcb PCB pointer
 * @return PCB ID
 */
static int udp_pcb_id(struct udp_pcb *pcb)
{
    return indexof(pcbs, pcb);
}

/* ============================================================================
 * UDP Packet Processing
 * ============================================================================

/**
 * @brief Process incoming UDP packet
 * @param data Packet data
 * @param len Packet length
 * @param src Source IP address
 * @param dst Destination IP address
 * @param iface Receiving interface
 */
static void udp_input(const uint8_t *data, size_t len, ip_addr_t src, 
                     ip_addr_t dst, struct ip_iface *iface)
{
    struct pseudo_hdr pseudo;
    uint16_t psum = 0;
    struct udp_hdr *hdr;
    char addr1[IP_ADDR_STR_LEN];
    char addr2[IP_ADDR_STR_LEN];
    struct udp_pcb *pcb;
    struct udp_queue_entry *entry;

    /* Validate packet length */
    if (len < sizeof(*hdr)) {
        errorf("too short");
        return;
    }
    
    hdr = (struct udp_hdr *)data;
    
    /* Validate length field */
    if (len != ntoh16(hdr->len)) {
        errorf("length error: len=%zu, hdr->len=%u", len, ntoh16(hdr->len));
        return;
    }
    
    /* Verify UDP checksum with pseudo-header */
    pseudo.src = src;
    pseudo.dst = dst;
    pseudo.zero = 0;
    pseudo.protocol = IP_PROTOCOL_UDP;
    pseudo.len = hton16(len);
    psum = ~cksum16((uint16_t *)&pseudo, sizeof(pseudo), 0);
    if (cksum16((uint16_t *)hdr, len, psum) != 0) {
        errorf("checksum error: sum=0x%04x, verify=0x%04x", 
               ntoh16(hdr->sum), ntoh16(cksum16((uint16_t *)hdr, len, -hdr->sum + psum)));
        return;
    }
    
    debugf("%s:%d => %s:%d, len=%zu (payload=%zu)",
        ip_addr_ntop(src, addr1, sizeof(addr1)), ntoh16(hdr->src),
        ip_addr_ntop(dst, addr2, sizeof(addr2)), ntoh16(hdr->dst),
        len, len - sizeof(*hdr));
    udp_dump(data, len);
    
    /* Find matching PCB with mutex protection */
    mutex_lock(&mutex);
    pcb = udp_pcb_select(dst, hdr->dst);
    if (!pcb) {
        /* No socket bound to this port - silently drop */
        mutex_unlock(&mutex);
        return;
    }
    
    /* Allocate queue entry with datagram data */
    entry = memory_alloc(sizeof(*entry) + (len - sizeof(*hdr)));
    if (!entry) {
        mutex_unlock(&mutex);
        errorf("memory_alloc() failure");
        return;
    }
    
    /* Store source endpoint and data */
    entry->foreign.addr = src;
    entry->foreign.port = hdr->src;
    entry->len = len - sizeof(*hdr);
    memcpy(entry + 1, hdr + 1, entry->len);
    
    /* Add to receive queue and wakeup waiting receiver */
    if (!queue_push(&pcb->queue, entry)) {
        mutex_unlock(&mutex);
        errorf("queue_push() failure");
        return;
    }
    sched_wakeup(&pcb->ctx);
    mutex_unlock(&mutex);
}

/**
 * @brief Output UDP datagram
 * @param src Source endpoint
 * @param dst Destination endpoint
 * @param data Datagram payload
 * @param len Payload length
 * @return Bytes sent, -1 on error
 */
ssize_t udp_output(struct ip_endpoint *src, struct ip_endpoint *dst, 
                  const uint8_t *data, size_t len)
{
    uint8_t buf[IP_PAYLOAD_SIZE_MAX];
    struct udp_hdr *hdr;
    struct pseudo_hdr pseudo;
    uint16_t total, psum = 0;
    char ep1[IP_ENDPOINT_STR_LEN];
    char ep2[IP_ENDPOINT_STR_LEN];

    /* Validate payload length */
    if (len > IP_PAYLOAD_SIZE_MAX - sizeof(*hdr)) {
        errorf("too long");
        return -1;
    }
    
    /* Build UDP header */
    hdr = (struct udp_hdr *)buf;
    hdr->src = src->port;
    hdr->dst = dst->port;
    total = sizeof(*hdr) + len;
    hdr->len = hton16(total);
    hdr->sum = 0;
    memcpy(hdr + 1, data, len);
    
    /* Calculate UDP checksum with pseudo-header */
    pseudo.src = src->addr;
    pseudo.dst = dst->addr;
    pseudo.zero = 0;
    pseudo.protocol = IP_PROTOCOL_UDP;
    pseudo.len = hton16(total);
    psum = ~cksum16((uint16_t *)&pseudo, sizeof(pseudo), 0);
    hdr->sum = cksum16((uint16_t *)hdr, total, psum);
    
    debugf("%s => %s, len=%u (payload=%zu)",
        ip_endpoint_ntop(src, ep1, sizeof(ep1)), 
        ip_endpoint_ntop(dst, ep2, sizeof(ep2)), total, len);
    udp_dump((uint8_t *)hdr, total);
    
    /* Send via IP layer */
    if (ip_output(IP_PROTOCOL_UDP, (uint8_t *)hdr, total, src->addr, dst->addr) == -1) {
        errorf("ip_output() failure");
        return -1;
    }
    return len;
}

/* ============================================================================
 * Event Handling
 * ============================================================================

/**
 * @brief Event handler for UDP socket wakeups
 * @param arg Unused argument
 */
static void event_handler(void *arg)
{
    struct udp_pcb *pcb;

    mutex_lock(&mutex);
    for (pcb = pcbs; pcb < tailof(pcbs); pcb++) {
        if (pcb->state == UDP_PCB_STATE_OPEN) {
            sched_interrupt(&pcb->ctx);
        }
    }
    mutex_unlock(&mutex);
}

/* ============================================================================
 * UDP Module Initialization
 * ============================================================================

/**
 * @brief Initialize UDP protocol module
 * @return 0 on success, -1 on failure
 */
int udp_init(void)
{
    /* Register UDP protocol handler with IP layer */
    if (ip_protocol_register("UDP", IP_PROTOCOL_UDP, udp_input) == -1) {
        errorf("ip_protocol_register() failure");
        return -1;
    }
    
    /* Subscribe to network events for socket wakeups */
    net_event_subscribe(event_handler, NULL);
    return 0;
}

/* ============================================================================
 * UDP Socket Operations
 * ============================================================================

/**
 * @brief Create a UDP socket
 * @return Socket descriptor, -1 on failure
 */
int udp_open(void)
{
    struct udp_pcb *pcb;
    int id;

    mutex_lock(&mutex);
    pcb = udp_pcb_alloc();
    if (!pcb) {
        errorf("udp_pcb_alloc() failure");
        mutex_unlock(&mutex);
        return -1;
    }
    id = udp_pcb_id(pcb);
    mutex_unlock(&mutex);
    return id;
}

/**
 * @brief Close UDP socket
 * @param id Socket descriptor
 * @return 0 on success, -1 on failure
 */
int udp_close(int id)
{
    struct udp_pcb *pcb;

    mutex_lock(&mutex);
    pcb = udp_pcb_get(id);
    if (!pcb) {
        errorf("pcb not found, id=%d", id);
        mutex_unlock(&mutex);
        return -1;
    }
    udp_pcb_release(pcb);
    mutex_unlock(&mutex);
    return 0;
}

/**
 * @brief Bind UDP socket to local endpoint
 * @param id Socket descriptor
 * @param local Local endpoint to bind
 * @return 0 on success, -1 on failure
 */
int udp_bind(int id, struct ip_endpoint *local)
{
    struct udp_pcb *pcb, *exist;
    char ep1[IP_ENDPOINT_STR_LEN];
    char ep2[IP_ENDPOINT_STR_LEN];

    mutex_lock(&mutex);
    pcb = udp_pcb_get(id);
    if (!pcb) {
        errorf("pcb not found, id=%d", id);
        mutex_unlock(&mutex);
        return -1;
    }
    
    /* Check if local endpoint is already in use */
    exist = udp_pcb_select(local->addr, local->port);
    if (exist) {
        errorf("already in use, id=%d, want=%s, exist=%s",
            id, ip_endpoint_ntop(local, ep1, sizeof(ep1)), 
            ip_endpoint_ntop(&exist->local, ep2, sizeof(ep2)));
        mutex_unlock(&mutex);
        return -1;
    }
    
    pcb->local = *local;
    debugf("bound, id=%d, local=%s", id, ip_endpoint_ntop(&pcb->local, ep1, sizeof(ep1)));
    mutex_unlock(&mutex);
    return 0;
}

/**
 * @brief Send UDP datagram to specified endpoint
 * @param id Socket descriptor
 * @param data Data to send
 * @param len Data length
 * @param foreign Destination endpoint
 * @return Bytes sent, -1 on error
 */
ssize_t udp_sendto(int id, uint8_t *data, size_t len, struct ip_endpoint *foreign)
{
    struct udp_pcb *pcb;
    struct ip_endpoint local;
    struct ip_iface *iface;
    char addr[IP_ADDR_STR_LEN];
    uint32_t p;

    mutex_lock(&mutex);
    pcb = udp_pcb_get(id);
    if (!pcb) {
        errorf("pcb not found, id=%d", id);
        mutex_unlock(&mutex);
        return -1;
    }
    
    /* Determine local address */
    local.addr = pcb->local.addr;
    if (local.addr == IP_ADDR_ANY) {
        /* Select source address based on route to destination */
        iface = ip_route_get_iface(foreign->addr);
        if (!iface) {
            errorf("iface not found that can reach foreign address, addr=%s",
                ip_addr_ntop(foreign->addr, addr, sizeof(addr)));
            mutex_unlock(&mutex);
            return -1;
        }
        local.addr = iface->unicast;
        debugf("select local address, addr=%s", ip_addr_ntop(local.addr, addr, sizeof(addr)));
    }
    
    /* Assign dynamic source port if not bound */
    if (!pcb->local.port) {
        for (p = UDP_SOURCE_PORT_MIN; p <= UDP_SOURCE_PORT_MAX; p++) {
            if (!udp_pcb_select(local.addr, hton16(p))) {
                pcb->local.port = hton16(p);
                debugf("dynamic assign local port, port=%d", p);
                break;
            }
        }
        if (!pcb->local.port) {
            debugf("failed to dynamic assign local port, addr=%s", 
                   ip_addr_ntop(local.addr, addr, sizeof(addr)));
            mutex_unlock(&mutex);
            return -1;
        }
    }
    
    local.port = pcb->local.port;
    mutex_unlock(&mutex);
    
    /* Send datagram */
    return udp_output(&local, foreign, data, len);
}

/**
 * @brief Receive UDP datagram and get source endpoint
 * @param id Socket descriptor
 * @param buf Receive buffer
 * @param size Buffer size
 * @param foreign Source endpoint (output)
 * @return Bytes received, -1 on error
 */
ssize_t udp_recvfrom(int id, uint8_t *buf, size_t size, struct ip_endpoint *foreign)
{
    struct udp_pcb *pcb;
    struct udp_queue_entry *entry;
    ssize_t len;

    mutex_lock(&mutex);
    pcb = udp_pcb_get(id);
    if (!pcb) {
        errorf("pcb not found, id=%d", id);
        mutex_unlock(&mutex);
        return -1;
    }
    
    /* Wait for incoming datagram */
    while (!(entry = queue_pop(&pcb->queue))) {
        if (sched_sleep(&pcb->ctx, &mutex, NULL) == -1) {
            debugf("interrupted");
            mutex_unlock(&mutex);
            errno = EINTR;
            return -1;
        }
        if (pcb->state == UDP_PCB_STATE_CLOSING) {
            debugf("closed");
            udp_pcb_release(pcb);
            mutex_unlock(&mutex);
            return -1;
        }
    }
    mutex_unlock(&mutex);
    
    /* Return source endpoint if requested */
    if (foreign) {
        *foreign = entry->foreign;
    }
    
    /* Copy data to user buffer (truncate if necessary) */
    len = MIN(size, entry->len);
    memcpy(buf, entry + 1, len);
    memory_free(entry);
    
    return len;
}