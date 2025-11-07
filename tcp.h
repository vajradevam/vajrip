/**
 * @file tcp.h
 * @brief TCP protocol definitions and interfaces
 */

#ifndef TCP_H
#define TCP_H

#include <stdint.h>
#include <sys/types.h>

#include "ip.h"

/* TCP connection state constants (RFC 793) */
#define TCP_STATE_CLOSED       1  /* Closed - no connection */
#define TCP_STATE_LISTEN       2  /* Listening for connections */
#define TCP_STATE_SYN_SENT     3  /* SYN sent - active open */
#define TCP_STATE_SYN_RECEIVED 4  /* SYN received - simultaneous open */
#define TCP_STATE_ESTABLISHED  5  /* Connection established */
#define TCP_STATE_FIN_WAIT1    6  /* FIN wait 1 - sent FIN */
#define TCP_STATE_FIN_WAIT2    7  /* FIN wait 2 - received FIN ACK */
#define TCP_STATE_CLOSING      8  /* Closing - simultaneous close */
#define TCP_STATE_TIME_WAIT    9  /* Time wait - 2MSL timeout */
#define TCP_STATE_CLOSE_WAIT  10  /* Close wait - received FIN */
#define TCP_STATE_LAST_ACK    11  /* Last ACK - sent FIN, waiting for ACK */

/* TCP module initialization */
extern int tcp_init(void);

/* RFC 793 compliant TCP operations */
extern int tcp_open_rfc793(struct ip_endpoint *local, struct ip_endpoint *foreign, int active);
extern int tcp_state(int id);
extern int tcp_close(int id);
extern ssize_t tcp_send(int id, uint8_t *data, size_t len);
extern ssize_t tcp_receive(int id, uint8_t *buf, size_t size);

/* BSD socket compatible TCP operations */
extern int tcp_open(void);
extern int tcp_bind(int id, struct ip_endpoint *local);
extern int tcp_connect(int id, struct ip_endpoint *foreign);
extern int tcp_listen(int id, int backlog);
extern int tcp_accept(int id, struct ip_endpoint *foreign);

#endif /* TCP_H */