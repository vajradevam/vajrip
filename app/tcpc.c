/**
 * @file main.c
 * @brief TCP/IP network stack test application
 * 
 * Simple TCP client application demonstrating the custom TCP/IP stack
 * with loopback and Ethernet TAP device support.
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
#include "tcp.h"
#include "sock.h"

#include "driver/loopback.h"
#include "driver/ether_tap.h"

#include "test/test.h"

/* Signal handling flag */
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
    
    /* Initialize network stack */
    if (net_init() == -1) {
        errorf("net_init() failure");
        return -1;
    }
    
    /* Initialize loopback device */
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
    
    /* Initialize Ethernet TAP device */
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
    
    /* Set default gateway */
    if (ip_route_set_default_gateway(iface, DEFAULT_GATEWAY) == -1) {
        errorf("ip_route_set_default_gateway() failure");
        return -1;
    }
    
    /* Start network stack */
    if (net_run() == -1) {
        errorf("net_run() failure");
        return -1;
    }
    
    return 0;
}

/**
 * @brief Main application entry point
 * @param argc Argument count
 * @param argv Argument vector
 * @return 0 on success, -1 on failure
 */
int main(int argc, char *argv[])
{
    int opt, soc;
    long int port;
    struct sockaddr_in local = { .sin_family = AF_INET }, foreign;
    uint8_t buf[1024];

    /* ========================================================================
     * Command Line Argument Parsing
     * ======================================================================== */
    
    while ((opt = getopt(argc, argv, "s:p:")) != -1) {
        switch (opt) {
        case 's':
            /* Parse local IP address */
            if (ip_addr_pton(optarg, &local.sin_addr) == -1) {
                errorf("ip_addr_pton() failure, addr=%s", optarg);
                return -1;
            }
            break;
        case 'p':
            /* Parse local port number */
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
    
    /* Validate required arguments */
    if (argc - optind != 1) {
        fprintf(stderr, "Usage: %s [-s local_addr] [-p local_port] foreign_addr:port\n", argv[0]);
        return -1;
    }
    
    /* Parse foreign endpoint (destination) */
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
     * Application Logic - TCP Client
     * ======================================================================== */
    
    /* Create TCP socket */
    soc = sock_open(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (soc == -1) {
        errorf("sock_open() failure");
        return -1;
    }
    
    /* Bind to local address if specified */
    if (local.sin_port) {
        if (sock_bind(soc, (struct sockaddr *)&local, sizeof(local)) == -1) {
            errorf("sock_bind() failure");
            return -1;
        }
    }
    
    /* Connect to remote server */
    if (sock_connect(soc, (struct sockaddr *)&foreign, sizeof(foreign)) == -1) {
        errorf("sock_connect() failure");
        return -1;
    }
    
    infof("connection established");
    
    /* Main data transfer loop */
    while (!terminate) {
        /* Read input from stdin */
        if (!fgets((char *)buf, sizeof(buf), stdin)) {
            break;  /* EOF or error */
        }
        
        /* Send data over TCP connection */
        if (sock_send(soc, buf, strlen((char *)buf)) == -1) {
            errorf("sock_send() failure");
            break;
        }
    }
    
    /* Close socket */
    sock_close(soc);

    /* ========================================================================
     * Network Stack Cleanup
     * ======================================================================== */
    
    net_shutdown();
    return 0;
}