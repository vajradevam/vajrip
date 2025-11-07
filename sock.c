/**
 * @file sock.c
 * @brief Socket API implementation
 * 
 * Implements BSD socket compatible interface for TCP and UDP network communication.
 * Provides socket creation, binding, connection management, and data transfer.
 */

#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include "util.h"
#include "net.h"
#include "ip.h"
#include "udp.h"
#include "tcp.h"
#include "sock.h"

/* Socket table - fixed array of socket structures */
static struct sock socks[128];

/* ============================================================================
 * Socket Address Conversion Functions
 * ============================================================================

/**
 * @brief Convert socket address from text to binary form
 * @param p String representation of socket address
 * @param n Output buffer for binary socket address
 * @param size Size of output buffer
 * @return 0 on success, -1 on failure
 */
int sockaddr_pton(const char *p, struct sockaddr *n, size_t size)
{
    struct ip_endpoint ep;

    /* Parse as IP endpoint first */
    if (ip_endpoint_pton(p, &ep) == 0) {
        if (size < sizeof(struct sockaddr_in)) {
            return -1;
        }
        /* Fill sockaddr_in structure */
        ((struct sockaddr_in *)n)->sin_family = AF_INET;
        ((struct sockaddr_in *)n)->sin_port = ep.port;
        ((struct sockaddr_in *)n)->sin_addr = ep.addr;
        return 0;
    }
    return -1;
}

/**
 * @brief Convert socket address from binary to text form
 * @param n Binary socket address to convert
 * @param p Output buffer for string representation
 * @param size Size of output buffer
 * @return Pointer to string representation, NULL on failure
 */
char *sockaddr_ntop(const struct sockaddr *n, char *p, size_t size)
{
    struct ip_endpoint ep;

    switch (n->sa_family) {
    case AF_INET:
        if (size < IP_ENDPOINT_STR_LEN) {
            return NULL;
        }
        /* Extract IP endpoint from sockaddr_in */
        ep.port = ((struct sockaddr_in *)n)->sin_port;
        ep.addr = ((struct sockaddr_in *)n)->sin_addr;
        return ip_endpoint_ntop(&ep, p, size);
    }
    return NULL;
}

/* ============================================================================
 * Socket Management Internal Functions
 * ============================================================================

/**
 * @brief Allocate a new socket from the socket table
 * @return Pointer to allocated socket, NULL if no free sockets
 */
static struct sock *sock_alloc(void)
{
    struct sock *entry;

    /* Find first unused socket in table */
    for (entry = socks; entry < tailof(socks); entry++) {
        if (!entry->used) {
            entry->used = 1;
            return entry;
        }
    }
    return NULL;
}

/**
 * @brief Free a socket and reset its state
 * @param s Socket to free
 * @return 0 on success
 */
static int sock_free(struct sock *s)
{
    memset(s, 0, sizeof(*s));
    return 0;
}

/**
 * @brief Get socket by descriptor ID
 * @param id Socket descriptor
 * @return Pointer to socket, NULL if invalid ID
 */
static struct sock *sock_get(int id)
{
    if (id < 0 || id >= (int)countof(socks)) {
        /* Invalid socket descriptor */
        return NULL;
    }
    return &socks[id];
}

/* ============================================================================
 * Socket System Call Implementations
 * ============================================================================

/**
 * @brief Create a new socket
 * @param domain Communication domain (AF_*)
 * @param type Socket type (SOCK_*)
 * @param protocol Protocol type
 * @return Socket descriptor on success, -1 on failure
 */
int sock_open(int domain, int type, int protocol)
{
    struct sock *s;

    /* Validate parameters */
    if (domain != AF_INET) {
        return -1;
    }
    if (type != SOCK_STREAM && type != SOCK_DGRAM) {
        return -1;
    }
    if (protocol != 0) { 
        return -1;
    }
    
    /* Allocate socket structure */
    s = sock_alloc();
    if (!s) {
        return -1;
    }
    
    /* Initialize socket */
    s->family = domain;
    s->type = type;
    
    /* Create protocol-specific socket */
    switch (s->type) {
    case SOCK_STREAM:
        s->desc = tcp_open();  /* TCP socket */
        break;
    case SOCK_DGRAM:
        s->desc = udp_open();  /* UDP socket */
        break;
    }
    
    if (s->desc == -1) {
        return -1;
    }
    
    /* Return index as socket descriptor */
    return indexof(socks, s);
}

/**
 * @brief Close a socket
 * @param id Socket descriptor to close
 * @return 0 on success, -1 on failure
 */
int sock_close(int id)
{
    struct sock *s;

    s = sock_get(id);
    if (!s) {
        return -1;
    }
    
    /* Close protocol-specific socket */
    switch (s->type) {
    case SOCK_STREAM:
        tcp_close(s->desc);
        break;    
    case SOCK_DGRAM:
        udp_close(s->desc);
        break;
    default:
        return -1;
    }
    
    /* Free socket structure */
    return sock_free(s);
}

/**
 * @brief Receive a message and get source address (UDP)
 * @param id Socket descriptor
 * @param buf Buffer to store received data
 * @param n Size of buffer
 * @param addr Source address structure (output)
 * @param addrlen Size of address structure (input/output)
 * @return Number of bytes received, -1 on error
 */
ssize_t sock_recvfrom(int id, void *buf, size_t n, struct sockaddr *addr, int *addrlen)
{
    struct sock *s;
    struct ip_endpoint ep;
    int ret;

    s = sock_get(id);
    if (!s) {
        return -1;
    }
    
    /* Only for datagram sockets */
    if (s->type != SOCK_DGRAM) {
        return -1;
    }
    
    switch (s->family) {
    case AF_INET:
        /* Receive datagram with source endpoint */
        ret = udp_recvfrom(s->desc, (uint8_t *)buf, n, &ep);
        if (ret != -1) {
            /* Fill source address information */
            ((struct sockaddr_in *)addr)->sin_addr = ep.addr;
            ((struct sockaddr_in *)addr)->sin_port = ep.port;
        }
        return ret;
    }
    return -1;
}

/**
 * @brief Send a message to specified address (UDP)
 * @param id Socket descriptor
 * @param buf Data to send
 * @param n Size of data
 * @param addr Destination address
 * @param addrlen Size of address structure
 * @return Number of bytes sent, -1 on error
 */
ssize_t sock_sendto(int id, const void *buf, size_t n, const struct sockaddr *addr, int addrlen)
{
    struct sock *s;
    struct ip_endpoint ep;

    s = sock_get(id);
    if (!s) {
        return -1;
    }
    
    /* Only for datagram sockets */
    if (s->type != SOCK_DGRAM) {
        return -1;
    }
    
    switch (s->family) {
    case AF_INET:
        /* Extract destination endpoint from sockaddr */
        ep.addr = ((struct sockaddr_in *)addr)->sin_addr;
        ep.port = ((struct sockaddr_in *)addr)->sin_port;
        return udp_sendto(s->desc, (uint8_t *)buf, n, &ep);
    }
    return -1;
}

/**
 * @brief Bind a socket to a local address
 * @param id Socket descriptor
 * @param addr Local address to bind
 * @param addrlen Size of address structure
 * @return 0 on success, -1 on failure
 */
int sock_bind(int id, const struct sockaddr *addr, int addrlen)
{
    struct sock *s;
    struct ip_endpoint ep;

    s = sock_get(id);
    if (!s) {
        return -1;
    }
    
    switch (s->type) {
    case SOCK_STREAM:
        /* TCP socket binding */
        switch (s->family) {
        case AF_INET:
            ep.addr = ((struct sockaddr_in *)addr)->sin_addr;
            ep.port = ((struct sockaddr_in *)addr)->sin_port;
            return tcp_bind(s->desc, &ep);
        }
        return -1;
    case SOCK_DGRAM:
        /* UDP socket binding */
        switch (s->family) {
        case AF_INET:
            ep.addr = ((struct sockaddr_in *)addr)->sin_addr;
            ep.port = ((struct sockaddr_in *)addr)->sin_port;
            return udp_bind(s->desc, &ep);
        }
        return -1;
    }
    return -1;
}

/**
 * @brief Listen for incoming connections (TCP)
 * @param id Socket descriptor
 * @param backlog Maximum pending connections queue size
 * @return 0 on success, -1 on failure
 */
int sock_listen(int id, int backlog)
{
    struct sock *s;

    s = sock_get(id);
    if (!s) {
        return -1;
    }
    
    /* Only for stream sockets */
    if (s->type != SOCK_STREAM) {
        return -1;
    }
    
    switch (s->family) {
    case AF_INET:
        return tcp_listen(s->desc, backlog);
    }
    return -1;
}

/**
 * @brief Accept an incoming connection (TCP)
 * @param id Listening socket descriptor
 * @param addr Client address structure (output)
 * @param addrlen Size of address structure (input/output)
 * @return New socket descriptor for connection, -1 on error
 */
int sock_accept(int id, struct sockaddr *addr, int *addrlen)
{
    struct sock *s, *new_s;
    struct ip_endpoint ep;
    int ret;

    s = sock_get(id);
    if (!s) {
        return -1;
    }
    
    /* Only for stream sockets */
    if (s->type != SOCK_STREAM) {
        return -1;
    }
    
    switch (s->family) {
    case AF_INET:
        /* Accept connection and get client endpoint */
        ret = tcp_accept(s->desc, &ep);
        if (ret == -1) {
            return -1;
        }
        
        /* Fill client address information */
        ((struct sockaddr_in *)addr)->sin_family = s->family;
        ((struct sockaddr_in *)addr)->sin_addr = ep.addr;
        ((struct sockaddr_in *)addr)->sin_port = ep.port;
        
        /* Create new socket for the connection */
        new_s = sock_alloc();
        new_s->family = s->family;
        new_s->type = s->type;
        new_s->desc = ret;
        
        return indexof(socks, new_s);
    }
    return -1;
}

/**
 * @brief Connect to a remote address (TCP)
 * @param id Socket descriptor
 * @param addr Remote address to connect to
 * @param addrlen Size of address structure
 * @return 0 on success, -1 on failure
 */
int sock_connect(int id, const struct sockaddr *addr, int addrlen)
{
    struct sock *s;
    struct ip_endpoint ep;

    s = sock_get(id);
    if (!s) {
        return -1;
    }
    
    /* Only for stream sockets */
    if (s->type != SOCK_STREAM) {
        return -1;
    }
    
    switch (s->family) {
    case AF_INET:
        /* Extract server endpoint from sockaddr */
        ep.addr = ((struct sockaddr_in *)addr)->sin_addr;
        ep.port = ((struct sockaddr_in *)addr)->sin_port;
        return tcp_connect(s->desc, &ep);
    }
    return -1;
}

/**
 * @brief Receive data on connected socket (TCP)
 * @param id Socket descriptor
 * @param buf Buffer to store received data
 * @param n Size of buffer
 * @return Number of bytes received, -1 on error
 */
ssize_t sock_recv(int id, void *buf, size_t n)
{
    struct sock *s;

    s = sock_get(id);
    if (!s) {
        return -1;
    }
    
    /* Only for stream sockets */
    if (s->type != SOCK_STREAM) {
        return -1;
    }
    
    switch (s->family) {
    case AF_INET:
        return tcp_receive(s->desc, (uint8_t *)buf, n);
    }
    return -1;
}

/**
 * @brief Send data on connected socket (TCP)
 * @param id Socket descriptor
 * @param buf Data to send
 * @param n Size of data
 * @return Number of bytes sent, -1 on error
 */
ssize_t sock_send(int id, const void *buf, size_t n)
{
    struct sock *s;

    s = sock_get(id);
    if (!s) {
        return -1;
    }
    
    /* Only for stream sockets */
    if (s->type != SOCK_STREAM) {
        return -1;
    }
    
    switch (s->family) {
    case AF_INET:
        return tcp_send(s->desc, (uint8_t *)buf, n);
    }
    return -1;
}