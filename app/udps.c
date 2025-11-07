/**
 * @file udp_server.c
 * @brief UDP echo server using custom TCP/IP stack
 * 
 * Simple UDP server that receives datagrams and echoes them back to the sender.
 * Demonstrates connectionless UDP communication with datagram sockets.
 */

#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <unistd.h>
#include <sys/types.h>
#include <errno.h>

#include "util.h"
#include "net.h"
#include "ip.h"
#include "icmp.h"
#include "udp.h"
#include "sock.h"

#include "driver/loopback.h"
#include "driver/ether_tap.h"

#include "test/test.h"

/* Signal handling flag for graceful shutdown */
static volatile sig_atomic_t terminate;

/**
 * @brief Signal handler for graceful shutdown
 * @param s Signal number
 */
static void on_signal(int s)
{
    (void)s;
    terminate = 1;
    net_interrupt();  /* Interrupt network stack operations */
}

/**
 * @brief Initialize network stack and devices
 * @return 0 on success, -1 on failure
 */
static int setup(void)
{
    struct net_device *dev;
    struct ip_iface *iface;

    /* Set up signal handlers for graceful shutdown */
    signal(SIGINT, on_signal);
    
    /* Initialize network stack core */
    if (net_init() == -1) {
        errorf("net_init() failure");
        return -1;
    }
    
    /* Initialize loopback device for local testing */
    dev = loopback_init();
    if (!dev) {
        errorf("loopback_init() failure");
        return -1;
    }
    iface = ip_iface_alloc(LOOPBACK_IP_ADDR, LOOPBACK_NETMASK);
    if (!iface) {
        errorf("ip_iface_alloc() failure");
        return -1;
    }
    if (ip_iface_register(dev, iface) == -1) {
        errorf("ip_iface_register() failure");
        return -1;
    }
    
    /* Initialize Ethernet TAP device for external communication */
    dev = ether_tap_init(ETHER_TAP_NAME, ETHER_TAP_HW_ADDR);
    if (!dev) {
        errorf("ether_tap_init() failure");
        return -1;
    }
    iface = ip_iface_alloc(ETHER_TAP_IP_ADDR, ETHER_TAP_NETMASK);
    if (!iface) {
        errorf("ip_iface_alloc() failure");
        return -1;
    }
    if (ip_iface_register(dev, iface) == -1) {
        errorf("ip_iface_register() failure");
        return -1;
    }
    
    /* Configure default gateway for external routing */
    if (ip_route_set_default_gateway(iface, DEFAULT_GATEWAY) == -1) {
        errorf("ip_route_set_default_gateway() failure");
        return -1;
    }
    
    /* Start network stack operation */
    if (net_run() == -1) {
        errorf("net_run() failure");
        return -1;
    }
    
    return 0;
}

/**
 * @brief Main application entry point for UDP echo server
 * @param argc Argument count
 * @param argv Argument vector
 * @return 0 on success, -1 on failure
 */
int main(int argc, char *argv[])
{
    int soc;                          /* Socket descriptor */
    long int port;                    /* Server port number */
    struct sockaddr_in local = { .sin_family = AF_INET }, foreign;  /* Address structures */
    int foreignlen;                   /* Length of foreign address */
    uint8_t buf[1024];                /* Data buffer */
    char addr[SOCKADDR_STR_LEN];      /* String buffer for address formatting */
    ssize_t ret;                      /* Return value from socket operations */

    /* ========================================================================
     * Command Line Argument Parsing
     * ======================================================================== */
    
    switch (argc) {
    case 3:
        /* Parse local IP address if provided */
        if (ip_addr_pton(argv[argc-2], &local.sin_addr) == -1) {
            errorf("ip_addr_pton() failure, addr=%s", argv[argc-2]);
            return -1;
        }
        /* Fall through to port parsing */
    case 2:
        /* Parse port number */
        port = strtol(argv[argc-1], NULL, 10);
        if (port < 0 || port > UINT16_MAX) {
            errorf("invalid port, port=%s", argv[argc-1]);
            return -1;
        }
        local.sin_port = hton16(port);
        break;
    default:
        fprintf(stderr, "Usage: %s [addr] port\n", argv[0]);
        return -1;
    }

    /* ========================================================================
     * Network Stack Initialization
     * ======================================================================== */
    
    if (setup() == -1) {
        errorf("setup() failure");
        return -1;
    }

    /* ========================================================================
     * Application Logic - UDP Echo Server
     * ======================================================================== */
    
    /* Create UDP socket */
    soc = sock_open(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (soc == -1) {
        errorf("sock_open() failure");
        return -1;
    }
    
    /* Bind socket to local address and port */
    if (sock_bind(soc, (struct sockaddr *)&local, sizeof(local)) == -1) {
        errorf("sock_bind() failure");
        return -1;
    }
    
    infof("UDP echo server listening on %s:%d", 
          ip_addr_ntop(local.sin_addr, addr, sizeof(addr)), 
          ntoh16(local.sin_port));
    
    /* Main echo loop */
    while (!terminate) {
        /* Receive datagram from any client */
        foreignlen = sizeof(foreign);
        ret = sock_recvfrom(soc, buf, sizeof(buf), 
                           (struct sockaddr *)&foreign, &foreignlen);
        if (ret == -1) {
            if (errno == EINTR) {
                /* Interrupted by signal - continue */
                continue;
            }
            errorf("sock_recvfrom() failure");
            break;
        }
        
        /* Log received datagram */
        infof("%zu bytes data from %s", ret, 
              sockaddr_ntop((struct sockaddr *)&foreign, addr, sizeof(addr)));
        hexdump(stderr, buf, ret);
        
        /* Echo datagram back to sender */
        if (sock_sendto(soc, buf, ret, 
                       (struct sockaddr *)&foreign, foreignlen) == -1) {
            errorf("sock_sendto() failure");
            break;
        }
        
        infof("echoed %zu bytes back to %s", ret, 
              sockaddr_ntop((struct sockaddr *)&foreign, addr, sizeof(addr)));
    }
    
    /* Close socket */
    udp_close(soc);

    /* ========================================================================
     * Network Stack Cleanup
     * ======================================================================== */
    
    net_shutdown();
    return 0;
}