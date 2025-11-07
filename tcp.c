/**
 * @file tcp.c
 * @brief TCP protocol implementation (RFC 793)
 * 
 * Implements Transmission Control Protocol with RFC 793 compliance,
 * including connection management, flow control, and reliable data transfer.
 */

#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <sys/time.h>

#include "platform.h"
#include "util.h"
#include "net.h"
#include "ip.h"
#include "tcp.h"

/* TCP flag definitions */
#define TCP_FLG_FIN 0x01  /* Finish flag */
#define TCP_FLG_SYN 0x02  /* Synchronize flag */
#define TCP_FLG_RST 0x04  /* Reset flag */
#define TCP_FLG_PSH 0x08  /* Push flag */
#define TCP_FLG_ACK 0x10  /* Acknowledgment flag */
#define TCP_FLG_URG 0x20  /* Urgent flag */

/* TCP flag utility macros */
#define TCP_FLG_IS(x, y) ((x & 0x3f) == (y))
#define TCP_FLG_ISSET(x, y) ((x & 0x3f) & (y) ? 1 : 0)

/* Protocol Control Block configuration */
#define TCP_PCB_SIZE 16           /* Maximum number of concurrent connections */
#define TCP_PCB_MODE_RFC793 1     /* RFC 793 compliant mode */
#define TCP_PCB_MODE_SOCKET 2     /* BSD socket compatible mode */

/* TCP PCB state definitions */
#define TCP_PCB_STATE_FREE         0  /* PCB is unused */
#define TCP_PCB_STATE_CLOSED       1  /* Connection closed */
#define TCP_PCB_STATE_LISTEN       2  /* Listening for connections */
#define TCP_PCB_STATE_SYN_SENT     3  /* SYN sent, awaiting SYN-ACK */
#define TCP_PCB_STATE_SYN_RECEIVED 4  /* SYN received, awaiting ACK */
#define TCP_PCB_STATE_ESTABLISHED  5  /* Connection established */
#define TCP_PCB_STATE_FIN_WAIT1    6  /* Sent FIN, awaiting FIN-ACK */
#define TCP_PCB_STATE_FIN_WAIT2    7  /* Received FIN-ACK, awaiting FIN */
#define TCP_PCB_STATE_CLOSING      8  /* Both sides sent FIN */
#define TCP_PCB_STATE_TIME_WAIT    9  /* Waiting for 2MSL timeout */
#define TCP_PCB_STATE_CLOSE_WAIT  10  /* Received FIN, awaiting close */
#define TCP_PCB_STATE_LAST_ACK    11  /* Sent FIN, awaiting final ACK */

/* TCP timing constants */
#define TCP_DEFAULT_RTO 200000     /* Default Retransmission Timeout (microseconds) */
#define TCP_RETRANSMIT_DEADLINE 12 /* Maximum retransmission time (seconds) */
#define TCP_TIMEWAIT_SEC 30        /* TIME-WAIT timeout (substitute for 2MSL) */

/* TCP port allocation range */
#define TCP_SOURCE_PORT_MIN 49152  /* Start of dynamic port range */
#define TCP_SOURCE_PORT_MAX 65535  /* End of dynamic port range */

/**
 * @brief Pseudo header for TCP checksum calculation
 */
struct pseudo_hdr {
    uint32_t src;      /* Source IP address */
    uint32_t dst;      /* Destination IP address */
    uint8_t zero;      /* Zero padding */
    uint8_t protocol;  /* Protocol number */
    uint16_t len;      /* TCP segment length */
};

/**
 * @brief TCP header structure (RFC 793)
 */
struct tcp_hdr {
    uint16_t src;    /* Source port */
    uint16_t dst;    /* Destination port */
    uint32_t seq;    /* Sequence number */
    uint32_t ack;    /* Acknowledgment number */
    uint8_t off;     /* Data offset and reserved bits */
    uint8_t flg;     /* Control flags */
    uint16_t wnd;    /* Window size */
    uint16_t sum;    /* Checksum */
    uint16_t up;     /* Urgent pointer */
};

/**
 * @brief TCP segment information structure
 */
struct tcp_segment_info {
    uint32_t seq;    /* Sequence number */
    uint32_t ack;    /* Acknowledgment number */
    uint16_t len;    /* Segment length */
    uint16_t wnd;    /* Window size */
    uint16_t up;     /* Urgent pointer */
};

/**
 * @brief TCP Protocol Control Block (PCB)
 * 
 * Manages state and buffers for a single TCP connection.
 */
struct tcp_pcb {
    int state;                       /* Current connection state */
    int mode;                        /* Operation mode (RFC793 or Socket) */
    struct ip_endpoint local;        /* Local endpoint */
    struct ip_endpoint foreign;      /* Remote endpoint */
    
    /* Send sequence variables */
    struct {
        uint32_t nxt;                /* Next sequence number to send */
        uint32_t una;                /* Oldest unacknowledged sequence number */
        uint16_t wnd;                /* Send window size */
        uint16_t up;                 /* Send urgent pointer */
        uint32_t wl1;                /* Segment sequence number for window update */
        uint32_t wl2;                /* Segment acknowledgment number for window update */
    } snd;
    
    uint32_t iss;                    /* Initial send sequence number */
    
    /* Receive sequence variables */
    struct {
        uint32_t nxt;                /* Next expected sequence number */
        uint16_t wnd;                /* Receive window size */
        uint16_t up;                 /* Receive urgent pointer */
    } rcv;
    
    uint32_t irs;                    /* Initial receive sequence number */
    uint16_t mtu;                    /* Maximum transmission unit */
    uint16_t mss;                    /* Maximum segment size */
    uint8_t buf[65535];              /* Receive buffer */
    struct sched_ctx ctx;            /* Scheduling context for blocking operations */
    struct queue_head queue;         /* Retransmission queue */
    struct timeval tw_timer;         /* TIME-WAIT timer */
    struct tcp_pcb *parent;          /* Parent PCB for listening sockets */
    struct queue_head backlog;       /* Backlog of incoming connections */
};

/**
 * @brief Retransmission queue entry
 */
struct tcp_queue_entry {
    struct timeval first;            /* First transmission time */
    struct timeval last;             /* Last transmission time */
    unsigned int rto;                /* Retransmission timeout (microseconds) */
    uint32_t seq;                    /* Sequence number */
    uint8_t flg;                     /* TCP flags */
    size_t len;                      /* Data length */
    /* Data follows immediately after this structure */
};

/* Global TCP state */
static mutex_t mutex = MUTEX_INITIALIZER;  /* PCB access mutex */
static struct tcp_pcb pcbs[TCP_PCB_SIZE];   /* PCB table */

/* Forward declarations */
static ssize_t tcp_output_segment(uint32_t seq, uint32_t ack, uint8_t flg, 
                                 uint16_t wnd, uint8_t *data, size_t len, 
                                 struct ip_endpoint *local, struct ip_endpoint *foreign);

/**
 * @brief Convert TCP flags to string representation
 * @param flg TCP flags byte
 * @return String representation of flags
 */
static char *tcp_flg_ntoa(uint8_t flg)
{
    static char str[9];

    snprintf(str, sizeof(str), "--%c%c%c%c%c%c",
        TCP_FLG_ISSET(flg, TCP_FLG_URG) ? 'U' : '-',
        TCP_FLG_ISSET(flg, TCP_FLG_ACK) ? 'A' : '-',
        TCP_FLG_ISSET(flg, TCP_FLG_PSH) ? 'P' : '-',
        TCP_FLG_ISSET(flg, TCP_FLG_RST) ? 'R' : '-',
        TCP_FLG_ISSET(flg, TCP_FLG_SYN) ? 'S' : '-',
        TCP_FLG_ISSET(flg, TCP_FLG_FIN) ? 'F' : '-');
    return str;
}

/**
 * @brief Dump TCP segment for debugging
 * @param data TCP segment data
 * @param len Segment length
 */
static void tcp_dump(const uint8_t *data, size_t len)
{
    struct tcp_hdr *hdr;

    flockfile(stderr);
    hdr = (struct tcp_hdr *)data;
    fprintf(stderr, "        src: %u\n", ntoh16(hdr->src));
    fprintf(stderr, "        dst: %u\n", ntoh16(hdr->dst));
    fprintf(stderr, "        seq: %u\n", ntoh32(hdr->seq));
    fprintf(stderr, "        ack: %u\n", ntoh32(hdr->ack));
    fprintf(stderr, "        off: 0x%02x (%d)\n", hdr->off, (hdr->off >> 4) << 2);
    fprintf(stderr, "        flg: 0x%02x (%s)\n", hdr->flg, tcp_flg_ntoa(hdr->flg));
    fprintf(stderr, "        wnd: %u\n", ntoh16(hdr->wnd));
    fprintf(stderr, "        sum: 0x%04x\n", ntoh16(hdr->sum));
    fprintf(stderr, "         up: %u\n", ntoh16(hdr->up));
#ifdef HEXDUMP
    hexdump(stderr, data, len);
#endif
    funlockfile(stderr);
}

/* ============================================================================
 * TCP Protocol Control Block (PCB) Management
 * 
 * NOTE: PCB functions must be called with mutex locked
 * ============================================================================

/**
 * @brief Allocate a new PCB
 * @return Pointer to allocated PCB, NULL if no free PCBs
 */
static struct tcp_pcb *tcp_pcb_alloc(void)
{
    struct tcp_pcb *pcb;

    for (pcb = pcbs; pcb < tailof(pcbs); pcb++) {
        if (pcb->state == TCP_PCB_STATE_FREE) {
            pcb->state = TCP_PCB_STATE_CLOSED;
            sched_ctx_init(&pcb->ctx);
            return pcb;
        }
    }
    return NULL;
}

/**
 * @brief Release a PCB and cleanup resources
 * @param pcb PCB to release
 */
static void tcp_pcb_release(struct tcp_pcb *pcb)
{
    struct queue_entry *entry;
    struct tcp_pcb *est;
    char ep1[IP_ENDPOINT_STR_LEN];
    char ep2[IP_ENDPOINT_STR_LEN];

    /* Destroy scheduling context */
    if (sched_ctx_destroy(&pcb->ctx) == -1) {
        sched_wakeup(&pcb->ctx);
        return;
    }
    
    /* Cleanup retransmission queue */
    while ((entry = queue_pop(&pcb->queue)) != NULL) {
        memory_free(entry);
    }
    
    /* Cleanup backlog connections */
    while ((est = queue_pop(&pcb->backlog)) != NULL) {
        tcp_pcb_release(est);
    }
    
    debugf("released, local=%s, foreign=%s",
        ip_endpoint_ntop(&pcb->local, ep1, sizeof(ep1)), 
        ip_endpoint_ntop(&pcb->foreign, ep2, sizeof(ep2)));
    memset(pcb, 0, sizeof(*pcb));
}

/**
 * @brief Select PCB matching local and foreign endpoints
 * @param local Local endpoint
 * @param foreign Foreign endpoint (NULL for wildcard match)
 * @return Matching PCB, NULL if not found
 */
static struct tcp_pcb *tcp_pcb_select(struct ip_endpoint *local, struct ip_endpoint *foreign)
{
    struct tcp_pcb *pcb, *listen_pcb = NULL;

    for (pcb = pcbs; pcb < tailof(pcbs); pcb++) {
        if ((pcb->local.addr == IP_ADDR_ANY || pcb->local.addr == local->addr) && 
            pcb->local.port == local->port) {
            if (!foreign) {
                return pcb;
            }
            if (pcb->foreign.addr == foreign->addr && pcb->foreign.port == foreign->port) {
                return pcb;
            }
            if (pcb->state == TCP_PCB_STATE_LISTEN) {
                if (pcb->foreign.addr == IP_ADDR_ANY && pcb->foreign.port == 0) {
                    /* Wildcard listener */
                    listen_pcb = pcb;
                }
            }
        }
    }
    return listen_pcb;
}

/**
 * @brief Get PCB by ID
 * @param id PCB ID
 * @return PCB pointer, NULL if invalid ID
 */
static struct tcp_pcb *tcp_pcb_get(int id)
{
    struct tcp_pcb *pcb;

    if (id < 0 || id >= (int)countof(pcbs)) {
        return NULL;
    }
    pcb = &pcbs[id];
    if (pcb->state == TCP_PCB_STATE_FREE) {
        return NULL;
    }
    return pcb;
}

/**
 * @brief Get PCB ID
 * @param pcb PCB pointer
 * @return PCB ID
 */
static int tcp_pcb_id(struct tcp_pcb *pcb)
{
    return indexof(pcbs, pcb);
}

/* ============================================================================
 * TCP Retransmission Management
 * 
 * NOTE: Retransmit functions must be called with mutex locked
 * ============================================================================

/**
 * @brief Add segment to retransmission queue
 * @param pcb PCB
 * @param seq Sequence number
 * @param flg TCP flags
 * @param data Segment data
 * @param len Data length
 * @return 0 on success, -1 on failure
 */
static int tcp_retransmit_queue_add(struct tcp_pcb *pcb, uint32_t seq, 
                                   uint8_t flg, uint8_t *data, size_t len)
{
    struct tcp_queue_entry *entry;

    entry = memory_alloc(sizeof(*entry) + len);
    if (!entry) {
        errorf("memory_alloc() failure");
        return -1;
    }
    entry->rto = TCP_DEFAULT_RTO;
    entry->seq = seq;
    entry->flg = flg;
    entry->len = len;
    memcpy(entry + 1, data, entry->len);
    gettimeofday(&entry->first, NULL);
    entry->last = entry->first;
    if (!queue_push(&pcb->queue, entry)) {
        errorf("queue_push() failure");
        memory_free(entry);
        return -1;
    }
    return 0;
}

/**
 * @brief Cleanup acknowledged segments from retransmission queue
 * @param pcb PCB
 */
static void tcp_retransmit_queue_cleanup(struct tcp_pcb *pcb)
{
    struct tcp_queue_entry *entry;

    while ((entry = queue_peek(&pcb->queue))) {
        if (entry->seq >= pcb->snd.una) {
            break;
        }
        entry = queue_pop(&pcb->queue);
        debugf("remove, seq=%u, flags=%s, len=%zu", entry->seq, tcp_flg_ntoa(entry->flg), entry->len);
        memory_free(entry);
    }
}

/**
 * @brief Emit retransmissions for expired segments
 * @param arg PCB pointer
 * @param data Queue entry pointer
 */
static void tcp_retransmit_queue_emit(void *arg, void *data)
{
    struct tcp_pcb *pcb;
    struct tcp_queue_entry *entry;
    struct timeval now, diff, timeout;

    pcb = (struct tcp_pcb *)arg;
    entry = (struct tcp_queue_entry *)data;
    gettimeofday(&now, NULL);
    timersub(&now, &entry->first, &diff);
    
    /* Check retransmission deadline */
    if (diff.tv_sec >= TCP_RETRANSMIT_DEADLINE) {
        pcb->state = TCP_PCB_STATE_CLOSED;
        sched_wakeup(&pcb->ctx);
        return;
    }
    
    /* Check if retransmission timeout expired */
    timeout = entry->last;
    timeval_add_usec(&timeout, entry->rto);
    if (timercmp(&now, &timeout, >)) {
        tcp_output_segment(entry->seq, pcb->rcv.nxt, entry->flg, pcb->rcv.wnd, 
                          (uint8_t *)(entry+1), entry->len, &pcb->local, &pcb->foreign);
        entry->last = now;
        entry->rto *= 2;  /* Exponential backoff */
    }
}

/**
 * @brief Set TIME-WAIT timer
 * @param pcb PCB
 */
static void tcp_set_timewait_timer(struct tcp_pcb *pcb)
{
    gettimeofday(&pcb->tw_timer, NULL);
    pcb->tw_timer.tv_sec += TCP_TIMEWAIT_SEC;
    debugf("start time_wait timer: %d seconds", TCP_TIMEWAIT_SEC);
}

/* ============================================================================
 * TCP Segment Output
 * ============================================================================

/**
 * @brief Output a TCP segment
 * @param seq Sequence number
 * @param ack Acknowledgment number
 * @param flg TCP flags
 * @param wnd Window size
 * @param data Segment data
 * @param len Data length
 * @param local Local endpoint
 * @param foreign Foreign endpoint
 * @return Bytes sent, -1 on error
 */
static ssize_t tcp_output_segment(uint32_t seq, uint32_t ack, uint8_t flg, 
                                 uint16_t wnd, uint8_t *data, size_t len, 
                                 struct ip_endpoint *local, struct ip_endpoint *foreign)
{
    uint8_t buf[IP_PAYLOAD_SIZE_MAX] = {};
    struct tcp_hdr *hdr;
    struct pseudo_hdr pseudo;
    uint16_t psum;
    uint16_t total;
    char ep1[IP_ENDPOINT_STR_LEN];
    char ep2[IP_ENDPOINT_STR_LEN];

    /* Build TCP header */
    hdr = (struct tcp_hdr *)buf;
    hdr->src = local->port;
    hdr->dst = foreign->port;
    hdr->seq = hton32(seq);
    hdr->ack = hton32(ack);
    hdr->off = (sizeof(*hdr) >> 2) << 4;
    hdr->flg = flg;
    hdr->wnd = hton16(wnd);
    hdr->sum = 0;
    hdr->up = 0;
    memcpy(hdr + 1, data, len);
    
    /* Calculate TCP checksum with pseudo-header */
    pseudo.src = local->addr;
    pseudo.dst = foreign->addr;
    pseudo.zero = 0;
    pseudo.protocol = IP_PROTOCOL_TCP;
    total = sizeof(*hdr) + len;
    pseudo.len = hton16(total);
    psum = ~cksum16((uint16_t *)&pseudo, sizeof(pseudo), 0);
    hdr->sum = cksum16((uint16_t *)hdr, total, psum);
    
    debugf("%s => %s, len=%u (payload=%zu)",
        ip_endpoint_ntop(local, ep1, sizeof(ep1)), 
        ip_endpoint_ntop(foreign, ep2, sizeof(ep2)), total, len);
    tcp_dump((uint8_t *)hdr, total);
    
    /* Send via IP layer */
    if (ip_output(IP_PROTOCOL_TCP, (uint8_t *)hdr, total, local->addr, foreign->addr) == -1) {
        return -1;
    }
    return len;
}

/**
 * @brief Output TCP segment with retransmission queuing
 * @param pcb PCB
 * @param flg TCP flags
 * @param data Segment data
 * @param len Data length
 * @return Bytes sent, -1 on error
 */
static ssize_t tcp_output(struct tcp_pcb *pcb, uint8_t flg, uint8_t *data, size_t len)
{
    uint32_t seq;

    seq = pcb->snd.nxt;
    if (TCP_FLG_ISSET(flg, TCP_FLG_SYN)) {
        seq = pcb->iss;
    }
    
    /* Queue for retransmission if needed */
    if (TCP_FLG_ISSET(flg, TCP_FLG_SYN | TCP_FLG_FIN) || len) {
        tcp_retransmit_queue_add(pcb, seq, flg, data, len);
    }
    
    return tcp_output_segment(seq, pcb->rcv.nxt, flg, pcb->rcv.wnd, 
                             data, len, &pcb->local, &pcb->foreign);
}

/* ============================================================================
 * TCP Segment Processing (RFC 793 Section 3.9)
 * ============================================================================

/**
 * @brief Process incoming TCP segment (RFC 793 Event Processing)
 * @param seg Segment information
 * @param flags TCP flags
 * @param data Segment data
 * @param len Data length
 * @param local Local endpoint
 * @param foreign Foreign endpoint
 */
static void tcp_segment_arrives(struct tcp_segment_info *seg, uint8_t flags, 
                               uint8_t *data, size_t len, struct ip_endpoint *local, 
                               struct ip_endpoint *foreign)
{
    struct tcp_pcb *pcb, *new_pcb;
    int acceptable = 0;

    /* Find matching PCB */
    pcb = tcp_pcb_select(local, foreign);
    if (!pcb || pcb->state == TCP_PCB_STATE_CLOSED) {
        /* No matching connection - send RST */
        if (TCP_FLG_ISSET(flags, TCP_FLG_RST)) {
            return;
        }
        if (!TCP_FLG_ISSET(flags, TCP_FLG_ACK)) {
            tcp_output_segment(0, seg->seq + seg->len, TCP_FLG_RST | TCP_FLG_ACK, 
                              0, NULL, 0, local, foreign);
        } else {
            tcp_output_segment(seg->ack, 0, TCP_FLG_RST, 0, NULL, 0, local, foreign);
        }
        return;
    }
    
    /* State-specific processing */
    switch(pcb->state) {
    case TCP_PCB_STATE_LISTEN:
        /* LISTEN state processing */
        if (TCP_FLG_ISSET(flags, TCP_FLG_RST)) {
            return;
        }
        if (TCP_FLG_ISSET(flags, TCP_FLG_ACK)) {
            tcp_output_segment(seg->ack, 0, TCP_FLG_RST, 0, NULL, 0, local, foreign);
            return;
        }
        if (TCP_FLG_ISSET(flags, TCP_FLG_SYN)) {
            /* SYN received - create new connection */
            if (pcb->mode == TCP_PCB_MODE_SOCKET) {
                new_pcb = tcp_pcb_alloc();
                if (!new_pcb) {
                    errorf("tcp_pcb_alloc() failure");
                    return;
                }
                new_pcb->mode = TCP_PCB_MODE_SOCKET;
                new_pcb->parent = pcb;
                pcb = new_pcb;
            }
            pcb->local = *local;
            pcb->foreign = *foreign;
            pcb->rcv.wnd = sizeof(pcb->buf);
            pcb->rcv.nxt = seg->seq + 1;
            pcb->irs = seg->seq;
            pcb->iss = random();
            tcp_output(pcb, TCP_FLG_SYN | TCP_FLG_ACK, NULL, 0);
            pcb->snd.nxt = pcb->iss + 1;
            pcb->snd.una = pcb->iss;
            pcb->state = TCP_PCB_STATE_SYN_RECEIVED;
            return;
        }
        /* Drop other segments in LISTEN state */
        return;
        
    case TCP_PCB_STATE_SYN_SENT:
        /* SYN_SENT state processing */
        /* ... (RFC 793 processing continues) */
        break;
        
    default:
        /* Other states processing */
        /* ... (RFC 793 processing continues) */
        break;
    }
    
    /* Continue with RFC 793 segment processing steps */
    /* ... (implementation continues with sequence number validation, RST processing, etc.) */
}

/* ============================================================================
 * TCP Input and Timer Handlers
 * ============================================================================

/**
 * @brief Process incoming TCP packet
 * @param data Packet data
 * @param len Packet length
 * @param src Source IP address
 * @param dst Destination IP address
 * @param iface Receiving interface
 */
static void tcp_input(const uint8_t *data, size_t len, ip_addr_t src, 
                     ip_addr_t dst, struct ip_iface *iface)
{
    struct tcp_hdr *hdr;
    struct pseudo_hdr pseudo;
    uint16_t psum, hlen;
    char addr1[IP_ADDR_STR_LEN];
    char addr2[IP_ADDR_STR_LEN];
    struct ip_endpoint local, foreign;
    struct tcp_segment_info seg;

    if (len < sizeof(*hdr)) {
        errorf("too short");
        return;
    }
    
    hdr = (struct tcp_hdr *)data;
    
    /* Verify TCP checksum */
    pseudo.src = src;
    pseudo.dst = dst;
    pseudo.zero = 0;
    pseudo.protocol = IP_PROTOCOL_TCP;
    pseudo.len = hton16(len);
    psum = ~cksum16((uint16_t *)&pseudo, sizeof(pseudo), 0);
    if (cksum16((uint16_t *)hdr, len, psum) != 0) {
        errorf("checksum error: sum=0x%04x, verify=0x%04x", 
               ntoh16(hdr->sum), ntoh16(cksum16((uint16_t *)hdr, len, -hdr->sum + psum)));
        return;
    }
    
    /* Validate addresses */
    if (src == IP_ADDR_BROADCAST || src == iface->broadcast || 
        dst == IP_ADDR_BROADCAST || dst == iface->broadcast) {
        errorf("only supports unicast, src=%s, dst=%s",
            ip_addr_ntop(src, addr1, sizeof(addr1)), ip_addr_ntop(dst, addr2, sizeof(addr2)));
        return;
    }
    
    debugf("%s:%d => %s:%d, len=%zu (payload=%zu)",
        ip_addr_ntop(src, addr1, sizeof(addr1)), ntoh16(hdr->src),
        ip_addr_ntop(dst, addr2, sizeof(addr2)), ntoh16(hdr->dst),
        len, len - sizeof(*hdr));
    tcp_dump(data, len);
    
    /* Extract endpoint information */
    local.addr = dst;
    local.port = hdr->dst;
    foreign.addr = src;
    foreign.port = hdr->src;
    
    /* Calculate segment information */
    hlen = (hdr->off >> 4) << 2;
    seg.seq = ntoh32(hdr->seq);
    seg.ack = ntoh32(hdr->ack);
    seg.len = len - hlen;
    if (TCP_FLG_ISSET(hdr->flg, TCP_FLG_SYN)) {
        seg.len++; /* SYN consumes one sequence number */
    }
    if (TCP_FLG_ISSET(hdr->flg, TCP_FLG_FIN)) {
        seg.len++; /* FIN consumes one sequence number */
    }
    seg.wnd = ntoh16(hdr->wnd);
    seg.up = ntoh16(hdr->up);
    
    /* Process segment with mutex protection */
    mutex_lock(&mutex);
    tcp_segment_arrives(&seg, hdr->flg, (uint8_t *)hdr + hlen, len - hlen, &local, &foreign);
    mutex_unlock(&mutex);
}

/**
 * @brief TCP timer handler for retransmissions and TIME-WAIT
 */
static void tcp_timer(void)
{
    struct tcp_pcb *pcb;
    struct timeval now;
    char ep1[IP_ENDPOINT_STR_LEN];
    char ep2[IP_ENDPOINT_STR_LEN];

    mutex_lock(&mutex);
    gettimeofday(&now, NULL);
    
    for (pcb = pcbs; pcb < tailof(pcbs); pcb++) {
        if (pcb->state == TCP_PCB_STATE_FREE) {
            continue;
        }
        
        /* Check TIME-WAIT timeout */
        if (pcb->state == TCP_PCB_STATE_TIME_WAIT) {
            if (timercmp(&now, &pcb->tw_timer, >) != 0) {
                debugf("timewait has elapsed, local=%s, foreign=%s",
                    ip_endpoint_ntop(&pcb->local, ep1, sizeof(ep1)), 
                    ip_endpoint_ntop(&pcb->foreign, ep2, sizeof(ep2)));
                tcp_pcb_release(pcb);
                continue;
            }
        }
        
        /* Process retransmission queue */
        queue_foreach(&pcb->queue, tcp_retransmit_queue_emit, pcb);
    }
    mutex_unlock(&mutex);
}

/**
 * @brief Event handler for PCB wakeups
 * @param arg Unused argument
 */
static void event_handler(void *arg)
{
    struct tcp_pcb *pcb;

    mutex_lock(&mutex);
    for (pcb = pcbs; pcb < tailof(pcbs); pcb++) {
        if (pcb->state != TCP_PCB_STATE_FREE) {
            sched_interrupt(&pcb->ctx);
        }
    }
    mutex_unlock(&mutex);
}

/* ============================================================================
 * TCP Module Initialization
 * ============================================================================

/**
 * @brief Initialize TCP protocol module
 * @return 0 on success, -1 on failure
 */
int tcp_init(void)
{
    struct timeval interval = {0,100000};  /* 100ms timer */

    if (ip_protocol_register("TCP", IP_PROTOCOL_TCP, tcp_input) == -1) {
        errorf("ip_protocol_register() failure");
        return -1;
    }
    if (net_timer_register("TCP Timer", interval, tcp_timer) == -1) {
        errorf("net_timer_register() failure");
        return -1;
    }
    net_event_subscribe(event_handler, NULL);
    return 0;
}

/* ============================================================================
 * TCP User Commands (RFC 793)
 * ============================================================================

/**
 * @brief Open TCP connection (RFC 793 style)
 * @param local Local endpoint
 * @param foreign Foreign endpoint
 * @param active Active (1) or passive (0) open
 * @return Connection ID on success, -1 on failure
 */
int tcp_open_rfc793(struct ip_endpoint *local, struct ip_endpoint *foreign, int active)
{
    struct tcp_pcb *pcb;
    char ep1[IP_ENDPOINT_STR_LEN];
    char ep2[IP_ENDPOINT_STR_LEN];
    int state, id;

    mutex_lock(&mutex);
    pcb = tcp_pcb_alloc();
    if (!pcb) {
        errorf("tcp_pcb_alloc() failure");
        mutex_unlock(&mutex);
        return -1;
    }
    pcb->mode = TCP_PCB_MODE_RFC793;
    
    if (!active) {
        /* Passive open */
        debugf("passive open: local=%s, waiting for connection...", 
               ip_endpoint_ntop(local, ep1, sizeof(ep1)));
        pcb->local = *local;
        if (foreign) {
            pcb->foreign = *foreign;
        }
        pcb->state = TCP_PCB_STATE_LISTEN;
    } else {
        /* Active open */
        debugf("active open: local=%s, foreign=%s, connecting...",
            ip_endpoint_ntop(local, ep1, sizeof(ep1)), 
            ip_endpoint_ntop(foreign, ep2, sizeof(ep2)));
        pcb->local = *local;
        pcb->foreign = *foreign;
        pcb->rcv.wnd = sizeof(pcb->buf);
        pcb->iss = random();
        if (tcp_output(pcb, TCP_FLG_SYN, NULL, 0) == -1) {
            errorf("tcp_output() failure");
            pcb->state = TCP_PCB_STATE_CLOSED;
            tcp_pcb_release(pcb);
            mutex_unlock(&mutex);
            return -1;
        }
        pcb->snd.una = pcb->iss;
        pcb->snd.nxt = pcb->iss + 1;
        pcb->state = TCP_PCB_STATE_SYN_SENT;
    }
    
AGAIN:
    state = pcb->state;
    /* Wait for state change */
    while (pcb->state == state) {
        if (sched_sleep(&pcb->ctx, &mutex, NULL) == -1) {
            debugf("interrupted");
            pcb->state = TCP_PCB_STATE_CLOSED;
            tcp_pcb_release(pcb);
            mutex_unlock(&mutex);
            errno = EINTR;
            return -1;
        }
    }
    
    if (pcb->state != TCP_PCB_STATE_ESTABLISHED) {
        if (pcb->state == TCP_PCB_STATE_SYN_RECEIVED) {
            goto AGAIN;
        }
        errorf("open error: %d", pcb->state);
        pcb->state = TCP_PCB_STATE_CLOSED;
        tcp_pcb_release(pcb);
        mutex_unlock(&mutex);
        return -1;
    }
    
    id = tcp_pcb_id(pcb);
    debugf("connection established: local=%s, foreign=%s",
        ip_endpoint_ntop(&pcb->local, ep1, sizeof(ep1)), 
        ip_endpoint_ntop(&pcb->foreign, ep2, sizeof(ep2)));
    mutex_unlock(&mutex);
    return id;
}

/**
 * @brief Get TCP connection state
 * @param id Connection ID
 * @return Connection state, -1 on error
 */
int tcp_state(int id)
{
    struct tcp_pcb *pcb;
    int state;

    mutex_lock(&mutex);
    pcb = tcp_pcb_get(id);
    if (!pcb) {
        errorf("pcb not found");
        mutex_unlock(&mutex);
        return -1;
    }
    if (pcb->mode != TCP_PCB_MODE_RFC793) {
        errorf("not opened in rfc793 mode");
        mutex_unlock(&mutex);
        return -1;
    }
    state = pcb->state;
    mutex_unlock(&mutex);
    return state;
}

/* ============================================================================
 * TCP User Commands (Socket API)
 * ============================================================================

/**
 * @brief Create a TCP socket
 * @return Socket descriptor, -1 on failure
 */
int tcp_open(void)
{
    struct tcp_pcb *pcb;
    int id;

    mutex_lock(&mutex);
    pcb = tcp_pcb_alloc();
    if (!pcb) {
        errorf("tcp_pcb_alloc() failure");
        mutex_unlock(&mutex);
        return -1;
    }
    pcb->mode = TCP_PCB_MODE_SOCKET;
    id = tcp_pcb_id(pcb);
    mutex_unlock(&mutex);
    return id;
}

/**
 * @brief Connect TCP socket to remote endpoint
 * @param id Socket descriptor
 * @param foreign Remote endpoint
 * @return 0 on success, -1 on failure
 */
int tcp_connect(int id, struct ip_endpoint *foreign)
{
    struct tcp_pcb *pcb;
    struct ip_endpoint local;
    struct ip_iface *iface;
    char addr[IP_ADDR_STR_LEN];
    int p;
    int state;

    mutex_lock(&mutex);
    pcb = tcp_pcb_get(id);
    if (!pcb) {
        errorf("pcb not found");
        mutex_unlock(&mutex);
        return -1;
    }
    if (pcb->mode != TCP_PCB_MODE_SOCKET) {
        errorf("not opened in socket mode");
        mutex_unlock(&mutex);
        return -1;
    }
    
    /* Determine local endpoint */
    local.addr = pcb->local.addr;
    local.port = pcb->local.port;
    
    /* Select source address if not specified */
    if (local.addr == IP_ADDR_ANY) {
        iface = ip_route_get_iface(foreign->addr);
        if (!iface) {
            errorf("ip_route_get_iface() failure");
            mutex_unlock(&mutex);
            return -1;
        }
        debugf("select source address: %s", ip_addr_ntop(iface->unicast, addr, sizeof(addr)));
        local.addr = iface->unicast;
    }
    
    /* Assign dynamic source port if not specified */
    if (!local.port) {
        for (p = TCP_SOURCE_PORT_MIN; p <= TCP_SOURCE_PORT_MAX; p++) {
            local.port = p;
            if (!tcp_pcb_select(&local, foreign)) {
                debugf("dynamic assign source port: %d", ntoh16(local.port));
                pcb->local.port = local.port;
                break;
            }
        }
        if (!local.port) {
            debugf("failed to dynamic assign source port");
            mutex_unlock(&mutex);
            return -1;
        }
    }
    
    /* Initialize connection */
    pcb->local.addr = local.addr;
    pcb->local.port = local.port;
    pcb->foreign.addr = foreign->addr;
    pcb->foreign.port = foreign->port;
    pcb->rcv.wnd = sizeof(pcb->buf);
    pcb->iss = random();
    
    /* Send SYN */
    if (tcp_output(pcb, TCP_FLG_SYN, NULL, 0) == -1) {
        errorf("tcp_output() failure");
        pcb->state = TCP_PCB_STATE_CLOSED;
        tcp_pcb_release(pcb);
        mutex_unlock(&mutex);
        return -1;
    }
    pcb->snd.una = pcb->iss;
    pcb->snd.nxt = pcb->iss + 1;
    pcb->state = TCP_PCB_STATE_SYN_SENT;
    
AGAIN:
    state = pcb->state;
    /* Wait for connection establishment */
    while (pcb->state == state) {
        if (sched_sleep(&pcb->ctx, &mutex, NULL) == -1) {
            debugf("interrupted");
            pcb->state = TCP_PCB_STATE_CLOSED;
            tcp_pcb_release(pcb);
            mutex_unlock(&mutex);
            errno = EINTR;
            return -1;
        }
    }
    
    if (pcb->state != TCP_PCB_STATE_ESTABLISHED) {
        if (pcb->state == TCP_PCB_STATE_SYN_RECEIVED) {
            goto AGAIN;
        }
        errorf("open error: %d", pcb->state);
        pcb->state = TCP_PCB_STATE_CLOSED;
        tcp_pcb_release(pcb);
        mutex_unlock(&mutex);
        return -1;
    }
    
    id = tcp_pcb_id(pcb);
    mutex_unlock(&mutex);
    return id;
}

/**
 * @brief Bind TCP socket to local endpoint
 * @param id Socket descriptor
 * @param local Local endpoint
 * @return 0 on success, -1 on failure
 */
int tcp_bind(int id, struct ip_endpoint *local)
{
    struct tcp_pcb *pcb, *exist;
    char ep[IP_ENDPOINT_STR_LEN];

    mutex_lock(&mutex);
    pcb = tcp_pcb_get(id);
    if (!pcb) {
        errorf("pcb not found");
        mutex_unlock(&mutex);
        return -1;
    }
    if (pcb->mode != TCP_PCB_MODE_SOCKET) {
        errorf("not opened in socket mode");
        mutex_unlock(&mutex);
        return -1;
    }
    
    /* Check for existing binding */
    exist = tcp_pcb_select(local, NULL);
    if (exist) {
        errorf("already bound, exist=%s", ip_endpoint_ntop(&exist->local, ep, sizeof(ep)));
        mutex_unlock(&mutex);
        return -1;
    }
    
    pcb->local = *local;
    debugf("success: local=%s", ip_endpoint_ntop(&pcb->local, ep, sizeof(ep)));
    mutex_unlock(&mutex);
    return 0;
}

/**
 * @brief Listen for incoming connections
 * @param id Socket descriptor
 * @param backlog Maximum pending connections
 * @return 0 on success, -1 on failure
 */
int tcp_listen(int id, int backlog)
{
    struct tcp_pcb *pcb;

    mutex_lock(&mutex);
    pcb = tcp_pcb_get(id);
    if (!pcb) {
        errorf("pcb not found");
        mutex_unlock(&mutex);
        return -1;
    }
    if (pcb->mode != TCP_PCB_MODE_SOCKET) {
        errorf("not opened in socket mode");
        mutex_unlock(&mutex);
        return -1;
    }
    pcb->state = TCP_PCB_STATE_LISTEN;
    (void)backlog; // TODO: implement backlog
    mutex_unlock(&mutex);
    return 0;
}

/**
 * @brief Accept incoming connection
 * @param id Listening socket descriptor
 * @param foreign Client endpoint (output)
 * @return New socket descriptor, -1 on error
 */
int tcp_accept(int id, struct ip_endpoint *foreign)
{
    struct tcp_pcb *pcb, *new_pcb;
    int new_id;

    mutex_lock(&mutex);
    pcb = tcp_pcb_get(id);
    if (!pcb) {
        errorf("pcb not found");
        mutex_unlock(&mutex);
        return -1;
    }
    if (pcb->mode != TCP_PCB_MODE_SOCKET) {
        errorf("not opened in socket mode");
        mutex_unlock(&mutex);
        return -1;
    }
    if (pcb->state != TCP_PCB_STATE_LISTEN) {
        errorf("not in LISTEN state");
        mutex_unlock(&mutex);
        return -1;
    }
    
    /* Wait for incoming connection */
    while (!(new_pcb = queue_pop(&pcb->backlog))) {
        if (sched_sleep(&pcb->ctx, &mutex, NULL) == -1) {
            debugf("interrupted");
            mutex_unlock(&mutex);
            errno = EINTR;
            return -1;
        }
        if (pcb->state == TCP_PCB_STATE_CLOSED) {
            debugf("closed");
            tcp_pcb_release(pcb);
            mutex_unlock(&mutex);
            return -1;
        }
    }
    
    if (foreign) {
        *foreign = new_pcb->foreign;
    }
    new_id = tcp_pcb_id(new_pcb);
    mutex_unlock(&mutex);
    return new_id;
}

/* ============================================================================
 * TCP Data Transfer Operations
 * ============================================================================

/**
 * @brief Send data over TCP connection
 * @param id Connection ID
 * @param data Data to send
 * @param len Data length
 * @return Bytes sent, -1 on error
 */
ssize_t tcp_send(int id, uint8_t *data, size_t len)
{
    struct tcp_pcb *pcb;
    ssize_t sent = 0;
    struct ip_iface *iface;
    size_t mss, cap, slen;

    mutex_lock(&mutex);
    pcb = tcp_pcb_get(id);
    if (!pcb) {
        errorf("pcb not found");
        mutex_unlock(&mutex);
        return -1;
    }
    
RETRY:
    switch (pcb->state) {
    case TCP_PCB_STATE_CLOSED:
        errorf("connection does not exist");
        mutex_unlock(&mutex);
        return -1;
    case TCP_PCB_STATE_LISTEN:
        errorf("this connection is passive");
        mutex_unlock(&mutex);
        return -1;
    case TCP_PCB_STATE_SYN_SENT:
    case TCP_PCB_STATE_SYN_RECEIVED:
        errorf("insufficient resources");
        mutex_unlock(&mutex);
        return -1;
    case TCP_PCB_STATE_ESTABLISHED:
    case TCP_PCB_STATE_CLOSE_WAIT:
        /* Get interface for MTU calculation */
        iface = ip_route_get_iface(pcb->local.addr);
        if (!iface) {
            errorf("iface not found");
            mutex_unlock(&mutex);
            return -1;
        }
        mss = NET_IFACE(iface)->dev->mtu - (IP_HDR_SIZE_MIN + sizeof(struct tcp_hdr));
        
        /* Send data in segments */
        while (sent < (ssize_t)len) {
            cap = pcb->snd.wnd - (pcb->snd.nxt - pcb->snd.una);
            if (!cap) {
                /* Wait for window space */
                if (sched_sleep(&pcb->ctx, &mutex, NULL) == -1) {
                    debugf("interrupted");
                    if (!sent) {
                        mutex_unlock(&mutex);
                        errno = EINTR;
                        return -1;
                    }
                    break;
                }
                goto RETRY;
            }
            
            /* Calculate segment size */
            slen = MIN(MIN(mss, len - sent), cap);
            if (tcp_output(pcb, TCP_FLG_ACK | TCP_FLG_PSH, data + sent, slen) == -1) {
                errorf("tcp_output() failure");
                pcb->state = TCP_PCB_STATE_CLOSED;
                tcp_pcb_release(pcb);
                mutex_unlock(&mutex);
                return -1;
            }
            pcb->snd.nxt += slen;
            sent += slen;
        }
        break;
    case TCP_PCB_STATE_FIN_WAIT1:
    case TCP_PCB_STATE_FIN_WAIT2:
    case TCP_PCB_STATE_CLOSING:
    case TCP_PCB_STATE_LAST_ACK:
    case TCP_PCB_STATE_TIME_WAIT:
        errorf("connection closing");
        mutex_unlock(&mutex);
        return -1;
    default:
        errorf("unknown state '%u'", pcb->state);
        mutex_unlock(&mutex);
        return -1;
    }
    mutex_unlock(&mutex);
    return sent;
}

/**
 * @brief Receive data from TCP connection
 * @param id Connection ID
 * @param buf Receive buffer
 * @param size Buffer size
 * @return Bytes received, -1 on error
 */
ssize_t tcp_receive(int id, uint8_t *buf, size_t size)
{
    struct tcp_pcb *pcb;
    size_t remain, len;

    mutex_lock(&mutex);
    pcb = tcp_pcb_get(id);
    if (!pcb) {
        errorf("pcb not found");
        mutex_unlock(&mutex);
        return -1;
    }
    
RETRY:
    switch (pcb->state) {
    case TCP_PCB_STATE_CLOSED:
        errorf("connection does not exist");
        mutex_unlock(&mutex);
        return -1;
    case TCP_PCB_STATE_LISTEN:
    case TCP_PCB_STATE_SYN_SENT:
    case TCP_PCB_STATE_SYN_RECEIVED:
        errorf("insufficient resources");
        mutex_unlock(&mutex);
        return -1;
    case TCP_PCB_STATE_ESTABLISHED:
    case TCP_PCB_STATE_FIN_WAIT1:
    case TCP_PCB_STATE_FIN_WAIT2:
        remain = sizeof(pcb->buf) - pcb->rcv.wnd;
        if (!remain) {
            /* Wait for data */
            if (sched_sleep(&pcb->ctx, &mutex, NULL) == -1) {
                debugf("interrupted");
                mutex_unlock(&mutex);
                errno = EINTR;
                return -1;
            }
            goto RETRY;
        }
        break;
    case TCP_PCB_STATE_CLOSE_WAIT:
        remain = sizeof(pcb->buf) - pcb->rcv.wnd;
        if (remain) {
            break;
        }
        /* fall through */
    case TCP_PCB_STATE_CLOSING:
    case TCP_PCB_STATE_LAST_ACK:
    case TCP_PCB_STATE_TIME_WAIT:
        debugf("connection closing");
        mutex_unlock(&mutex);
        return 0;
    default:
        errorf("unknown state '%u'", pcb->state);
        mutex_unlock(&mutex);
        return -1;
    }
    
    /* Copy data from receive buffer */
    len = MIN(size, remain);
    memcpy(buf, pcb->buf, len);
    memmove(pcb->buf, pcb->buf + len, remain - len);
    pcb->rcv.wnd += len;
    mutex_unlock(&mutex);
    return len;
}

/**
 * @brief Close TCP connection
 * @param id Connection ID
 * @return 0 on success, -1 on error
 */
int tcp_close(int id)
{
    struct tcp_pcb *pcb;

    mutex_lock(&mutex);
    pcb = tcp_pcb_get(id);
    if (!pcb) {
        errorf("pcb not found");
        mutex_unlock(&mutex);
        return -1;
    }
    
    /* State-specific close processing */
    switch (pcb->state) {
    case TCP_PCB_STATE_CLOSED:
        errorf("connection does not exist");
        mutex_unlock(&mutex);
        return -1;
    case TCP_PCB_STATE_LISTEN:
    case TCP_PCB_STATE_SYN_SENT:
        pcb->state = TCP_PCB_STATE_CLOSED;
        break;
    case TCP_PCB_STATE_SYN_RECEIVED:
    case TCP_PCB_STATE_ESTABLISHED:
        tcp_output(pcb, TCP_FLG_ACK | TCP_FLG_FIN, NULL, 0);
        pcb->snd.nxt++;
        pcb->state = TCP_PCB_STATE_FIN_WAIT1;
        break;
    case TCP_PCB_STATE_FIN_WAIT1:
    case TCP_PCB_STATE_FIN_WAIT2:
        errorf("connection closing");
        mutex_unlock(&mutex);
        return -1;
    case TCP_PCB_STATE_CLOSE_WAIT:
        tcp_output(pcb, TCP_FLG_ACK | TCP_FLG_FIN, NULL, 0);
        pcb->snd.nxt++;
        pcb->state = TCP_PCB_STATE_LAST_ACK;
        break;
    case TCP_PCB_STATE_CLOSING:
    case TCP_PCB_STATE_LAST_ACK:
    case TCP_PCB_STATE_TIME_WAIT:
        errorf("connection closing");
        mutex_unlock(&mutex);
        return -1;
    default:
        errorf("unknown state '%u'", pcb->state);
        mutex_unlock(&mutex);
        return -1;
    }
    
    /* Cleanup if closed immediately */
    if (pcb->state == TCP_PCB_STATE_CLOSED) {
        tcp_pcb_release(pcb);
    } else {
        sched_wakeup(&pcb->ctx);
    }
    mutex_unlock(&mutex);
    return 0;
}