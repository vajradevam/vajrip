/**
 * @file ping.c
 * @brief ICMP Echo Request (ping) test application
 * 
 * Sends periodic ICMP Echo Request packets to test network connectivity
 * and demonstrate ICMP protocol functionality in the custom TCP/IP stack.
 */

#include <stdio.h>
#include <stdint.h>
#include <signal.h>
#include <unistd.h>
#include <sys/types.h>

#include "util.h"
#include "net.h"
#include "ip.h"
#include "icmp.h"

#include "driver/null.h"
#include "driver/loopback.h"
#include "driver/ether_tap.h"

#include "test.h"

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
}

/**
 * @brief Main application entry point for ICMP ping test
 * @param argc Argument count
 * @param argv Argument vector
 * @return 0 on success, -1 on failure
 */
int main(int argc, char *argv[])
{
    int opt, noop = 0;                    /* Command line options */
    struct net_device *dev;               /* Network devices */
    struct ip_iface *iface;               /* IP interfaces */
    ip_addr_t src = IP_ADDR_ANY, dst;     /* Source and destination addresses */
    uint16_t id, seq = 0;                 /* ICMP identifier and sequence numbers */
    size_t offset = IP_HDR_SIZE_MIN + ICMP_HDR_SIZE;  /* Payload offset */

    /* ========================================================================
     * Command Line Argument Parsing
     * ======================================================================== */
    
    while ((opt = getopt(argc, argv, "n")) != -1) {
        switch (opt) {
        case 'n':
            /* No-operation mode - initialize stack but don't send packets */
            noop = 1;
            break;
        default:
            fprintf(stderr, "Usage: %s [-n] [src] dst\n", argv[0]);
            return -1;
        }
    }
    
    /* Parse source and destination addresses */
    switch (argc - optind) {
    case 2:
        /* Parse source IP address */
        if (ip_addr_pton(argv[optind], &src) == -1) {
            errorf("ip_addr_pton() failure, addr=%s", argv[optind]);
            return -1;
        }
        optind++;
        /* Fall through to parse destination */
    case 1:
        /* Parse destination IP address */
        if (ip_addr_pton(argv[optind], &dst) == -1) {
            errorf("ip_addr_pton() failure, addr=%s", argv[optind]);
            return -1;
        }
        optind++;
        break;
    case 0:
        /* No addresses provided - only valid in no-op mode */
        if (noop) {
            break;
        }
        /* Fall through to error */
    default:
        fprintf(stderr, "Usage: %s [-n] [src] dst\n", argv[0]);
        return -1;
    }

    /* ========================================================================
     * Network Stack Initialization
     * ======================================================================== */
    
    /* Set up signal handlers for graceful shutdown */
    signal(SIGINT, on_signal);
    
    /* Initialize network stack core */
    if (net_init() == -1) {
        errorf("net_init() failure");
        return -1;
    }
    
    /* Initialize null device (packet sink) */
    dev = null_init();
    if (!dev) {
        errorf("null_init() failure");
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

    /* ========================================================================
     * ICMP Ping Test Logic
     * ======================================================================== */
    
    /* Generate ICMP identifier from process ID */
    id = getpid() % UINT16_MAX;
    
    if (noop) {
        infof("No-op mode: network stack initialized but no packets will be sent");
    } else {
        infof("Starting ICMP ping to %s (ID: %u)", 
              ip_addr_ntop(dst, (char*)test_data, sizeof(test_data)), id);
    }
    
    /* Main ping loop */
    while (!terminate) {
        if (!noop) {
            /* Send ICMP Echo Request packet */
            if (icmp_output(ICMP_TYPE_ECHO, 0, 
                           hton32(id << 16 | ++seq),  /* Combine ID and sequence */
                           test_data + offset,        /* Payload data */
                           sizeof(test_data) - offset, /* Payload length */
                           src, dst) == -1) {
                errorf("icmp_output() failure");
                break;
            }
            
            infof("Sent ICMP Echo Request #%u to %s", seq,
                  ip_addr_ntop(dst, (char*)test_data, sizeof(test_data)));
        }
        
        /* Wait before sending next ping */
        sleep(1);
    }
    
    if (!noop) {
        infof("Ping test completed. Sent %u packets.", seq);
    }

    /* ========================================================================
     * Network Stack Cleanup
     * ======================================================================== */
    
    net_shutdown();
    return 0;
}