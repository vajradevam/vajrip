/**
 * @file udp_client.c
 * @brief UDP client using custom TCP/IP stack
 * 
 * Simple UDP client that sends user input to a specified server.
 * Demonstrates connectionless UDP communication with datagram sockets.
 */

#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <unistd.h>
#include <sys/types.h>

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
    net_interrupt();  /* Interrupt network stack */
    close(0);         /* Close stdin to break fgets() */
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
 * @brief Main application entry point for UDP client
 * @param argc Argument count
 * @param argv Argument vector
 * @return 0 on success, -1 on failure
 */
int main(int argc, char *argv[])
{
    int opt, soc;                    /* Socket descriptor */
    long int port;                   /* Port number */
    struct sockaddr_in local = { .sin_family = AF_INET }, foreign;  /* Address structures */
    uint8_t buf[1024];               /* Data buffer */

    /* ========================================================================
     * Command Line Argument Parsing
     * ======================================================================== */
    
    while ((opt = getopt(argc, argv, "s:p:")) != -1) {
        switch (opt) {
        case 's':
            /* Parse local IP address (optional) */
            if (ip_addr_pton(optarg, &local.sin_addr) == -1) {
                errorf("ip_addr_pton() failure, addr=%s", optarg);
                return -1;
            }
            break;
        case 'p':
            /* Parse local port number (optional) */
            port = strtol(optarg, NULL, 10);
            if (port < 0 || port > UINT16_MAX) {
                errorf("invalid port, port=%s", optarg);
                return -1;
            }
            local.sin_port = hton16(port);
            break;
        default:
            fprintf(stderr, "Usage: %s [-s local_addr] [-p local_port] foreign_addr:port\n", argv[0]);
            return -1;
        }
    }
    
    /* Validate required foreign endpoint argument */
    if (argc - optind != 1) {
        fprintf(stderr, "Usage: %s [-s local_addr] [-p local_port] foreign_addr:port\n", argv[0]);
        return -1;
    }
    
    /* Parse foreign endpoint (destination server) */
    if (sockaddr_pton(argv[optind], (struct sockaddr *)&foreign, sizeof(foreign)) == -1) {
        errorf("sockaddr_pton() failure, %s", argv[optind]);
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
     * Application Logic - UDP Client
     * ======================================================================== */
    
    /* Create UDP socket */
    soc = sock_open(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (soc == -1) {
        errorf("sock_open() failure");
        return -1;
    }
    
    /* Bind to local address if specified (optional) */
    if (local.sin_port) {
        if (sock_bind(soc, (struct sockaddr *)&local, sizeof(local)) == -1) {
            errorf("sock_bind() failure");
            return -1;
        }
    }
    
    infof("UDP client ready, sending to %s:%d", 
          ip_addr_ntop(foreign.sin_addr, (char*)buf, sizeof(buf)), 
          ntoh16(foreign.sin_port));
    
    /* Main data sending loop */
    while (!terminate) {
        /* Read input from stdin */
        if (!fgets((char *)buf, sizeof(buf), stdin)) {
            break;  /* EOF or error */
        }
        
        /* Send datagram to specified foreign endpoint */
        if (sock_sendto(soc, buf, strlen((char *)buf), 
                       (struct sockaddr *)&foreign, sizeof(foreign)) == -1) {
            errorf("sock_sendto() failure");
            break;
        }
        
        infof("sent %zu bytes to %s:%d", strlen((char *)buf),
              ip_addr_ntop(foreign.sin_addr, (char*)buf, sizeof(buf)), 
              ntoh16(foreign.sin_port));
    }
    
    /* Close socket */
    sock_close(soc);

    /* ========================================================================
     * Network Stack Cleanup
     * ======================================================================== */
    
    net_shutdown();
    return 0;
}