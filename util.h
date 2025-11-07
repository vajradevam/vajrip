/**
 * @file util.h
 * @brief Utility functions and macros for network stack
 */

#ifndef UTIL_H
#define UTIL_H

#include <stdio.h>
#include <stdint.h>
#include <unistd.h>

/* Min/max macros */
#ifndef MAX
#define MAX(x, y) ((x) > (y) ? (x) : (y))
#endif
#ifndef MIN
#define MIN(x, y) ((x) < (y) ? (x) : (y))
#endif

/* Array and pointer utilities */
#define countof(x) ((sizeof(x) / sizeof(*x)))          /* Number of elements in array */
#define tailof(x) (x + countof(x))                     /* Pointer to end of array */
#define indexof(x, y) (((uintptr_t)y - (uintptr_t)x) / sizeof(*y))  /* Index of element in array */

/* Time arithmetic macros */
#define timeval_add_usec(x, y)         \
    do {                               \
        (x)->tv_sec += y / 1000000;    \
        (x)->tv_usec += y % 1000000;   \
        if ((x)->tv_usec >= 1000000) { \
            (x)->tv_sec += 1;          \
            (x)->tv_usec -= 1000000;   \
        }                              \
    } while(0);

#define timespec_add_nsec(x, y)           \
    do {                                  \
        (x)->tv_sec += y / 1000000000;    \
        (x)->tv_nsec += y % 1000000000;   \
        if ((x)->tv_nsec >= 1000000000) { \
            (x)->tv_sec += 1;             \
            (x)->tv_nsec -= 1000000000;   \
        }                                 \
    } while(0);

/* Logging macros */
#define errorf(...) lprintf(stderr, 'E', __FILE__, __LINE__, __func__, __VA_ARGS__)
#define warnf(...)  lprintf(stderr, 'W', __FILE__, __LINE__, __func__, __VA_ARGS__)
#define infof(...)  lprintf(stderr, 'I', __FILE__, __LINE__, __func__, __VA_ARGS__)
#define debugf(...) lprintf(stderr, 'D', __FILE__, __LINE__, __func__, __VA_ARGS__)

/* Conditional hex dump */
#ifdef HEXDUMP
#define debugdump(...) hexdump(stderr, __VA_ARGS__)
#else
#define debugdump(...)
#endif

/* Logging function */
extern int lprintf(FILE *fp, int level, const char *file, int line, 
                  const char *func, const char *fmt, ...);

/* Debugging function */
extern void hexdump(FILE *fp, const void *data, size_t size);

/* Queue structure */
struct queue_entry;

struct queue_head {
    struct queue_entry *head;  /* First entry in queue */
    struct queue_entry *tail;  /* Last entry in queue */
    unsigned int num;          /* Number of entries */
};

/* Queue operations */
extern void queue_init(struct queue_head *queue);
extern void *queue_push(struct queue_head *queue, void *data);
extern void *queue_pop(struct queue_head *queue);
extern void *queue_peek(struct queue_head *queue);
extern void queue_foreach(struct queue_head *queue, 
                         void (*func)(void *arg, void *data), void *arg);

/* Byte order conversion */
extern uint16_t hton16(uint16_t h);
extern uint16_t ntoh16(uint16_t n);
extern uint32_t hton32(uint32_t h);
extern uint32_t ntoh32(uint32_t n);

/* Checksum calculation */
extern uint16_t cksum16(uint16_t *addr, uint16_t count, uint32_t init);

#endif /* UTIL_H */