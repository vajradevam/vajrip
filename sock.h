/**
 * @file sock.h
 * @brief Socket API definitions and interfaces
 */

#ifndef SOCK_H
#define SOCK_H

#include <stddef.h>
#include <stdint.h>

#include "ip.h"

/* Protocol family constants */
#define PF_UNSPEC   0  /* Unspecified protocol family */
#define PF_LOCAL    1  /* Local communication (Unix domain) */
#define PF_INET     2  /* IPv4 Internet protocols */
#define PF_INET6   10  /* IPv6 Internet protocols */

/* Address family constants */
#define AF_UNSPEC   PF_UNSPEC  /* Unspecified address family */
#define AF_LOCAL    PF_LOCAL   /* Local communication */
#define AF_INET     PF_INET    /* IPv4 address family */
#define AF_INET6    PF_INET6   /* IPv6 address family */

/* Socket type constants */
#define SOCK_STREAM 1  /* Stream socket (TCP) */
#define SOCK_DGRAM  2  /* Datagram socket (UDP) */

/* Protocol constants */
#define IPPROTO_TCP 0  /* TCP transport protocol */
#define IPPROTO_UDP 0  /* UDP transport protocol */

/* Special address constants */
#define INADDR_ANY ((ip_addr_t)0)  /* Bind to any available address */

/* Buffer size constants */
#define SOCKADDR_STR_LEN IP_ENDPOINT_STR_LEN  /* Socket address string length */

/**
 * @brief Socket control structure
 */
struct sock {
    int used;    /* Socket allocation flag (1 = in use, 0 = free) */
    int family;  /* Address family (AF_INET, etc.) */
    int type;    /* Socket type (SOCK_STREAM, SOCK_DGRAM) */
    int desc;    /* Protocol-specific descriptor */
};

/**
 * @brief Generic socket address structure
 */
struct sockaddr {
    unsigned short sa_family;  /* Address family */
    char sa_data[14];          /* Protocol-specific address data */
};

/**
 * @brief IPv4 socket address structure
 */
struct sockaddr_in {
    unsigned short sin_family;  /* Address family (AF_INET) */
    uint16_t sin_port;          /* Port number in network byte order */
    ip_addr_t sin_addr;         /* IPv4 address in network byte order */
};

/* Interface name size */
#define IFNAMSIZ 16

/* Socket address conversion functions */
extern int sockaddr_pton(const char *p, struct sockaddr *n, size_t size);
extern char *sockaddr_ntop(const struct sockaddr *n, char *p, size_t size);

/* Socket system calls */
extern int sock_open(int domain, int type, int protocol);
extern int sock_close(int id);
extern ssize_t sock_recvfrom(int id, void *buf, size_t n, struct sockaddr *addr, int *addrlen);
extern ssize_t sock_sendto(int id, const void *buf, size_t n, const struct sockaddr *addr, int addrlen);
extern int sock_bind(int id, const struct sockaddr *addr, int addrlen);
extern int sock_listen(int id, int backlog);
extern int sock_accept(int id, struct sockaddr *addr, int *addrlen);
extern int sock_connect(int id, const struct sockaddr *addr, int addrlen);
extern ssize_t sock_recv(int id, void *buf, size_t n);
extern ssize_t sock_send(int id, const void *buf, size_t n);

#endif /* SOCK_H */