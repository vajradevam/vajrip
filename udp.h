/**
 * @file udp.h
 * @brief UDP protocol definitions and interfaces
 */

#ifndef UDP_H
#define UDP_H

#include <stddef.h>
#include <stdint.h>

#include "ip.h"

/* UDP datagram output */
extern ssize_t udp_output(struct ip_endpoint *src, struct ip_endpoint *dst, 
                         const uint8_t *buf, size_t len);

/* UDP module initialization */
extern int udp_init(void);

/* UDP socket operations */
extern int udp_open(void);
extern int udp_bind(int index, struct ip_endpoint *local);
extern ssize_t udp_sendto(int id, uint8_t *buf, size_t len, struct ip_endpoint *foreign);
extern ssize_t udp_recvfrom(int id, uint8_t *buf, size_t size, struct ip_endpoint *foreign);
extern int udp_close(int id);

#endif /* UDP_H */