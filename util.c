/**
 * @file util.c
 * @brief Utility functions implementation for network stack
 */

#include <stdio.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <limits.h>
#include <ctype.h>
#include <time.h>
#include <sys/time.h>

#include "platform.h"
#include "util.h"

/* ============================================================================
 * Logging and Debugging Functions
 * ============================================================================

/**
 * @brief Log formatted message with timestamp and context
 * @param fp Output file stream
 * @param level Log level character (E=error, W=warning, I=info, D=debug)
 * @param file Source file name
 * @param line Source line number
 * @param func Function name
 * @param fmt Format string
 * @param ... Format arguments
 * @return Number of characters written
 */
int lprintf(FILE *fp, int level, const char *file, int line, 
           const char *func, const char *fmt, ...)
{
    struct timeval tv;
    struct tm tm;
    char timestamp[32];
    int n = 0;
    va_list ap;

    /* Thread-safe output with timestamp */
    flockfile(fp);
    gettimeofday(&tv, NULL);
    strftime(timestamp, sizeof(timestamp), "%T", localtime_r(&tv.tv_sec, &tm));
    n += fprintf(fp, "%s.%03d [%c] %s: ", timestamp, (int)(tv.tv_usec / 1000), level, func);
    va_start(ap, fmt);
    n += vfprintf(fp, fmt, ap);
    va_end(ap);
    n += fprintf(fp, " (%s:%d)\n", file, line);
    funlockfile(fp);
    return n;
}

/**
 * @brief Hex dump memory region in canonical format
 * @param fp Output file stream
 * @param data Memory region to dump
 * @param size Size of memory region
 */
void hexdump(FILE *fp, const void *data, size_t size)
{
    unsigned char *src;
    int offset, index;

    flockfile(fp);
    src = (unsigned char *)data;
    
    /* Print header */
    fprintf(fp, "+------+-------------------------------------------------+------------------+\n");
    
    /* Print 16 bytes per line */
    for(offset = 0; offset < (int)size; offset += 16) {
        /* Offset column */
        fprintf(fp, "| %04x | ", offset);
        
        /* Hex bytes column */
        for(index = 0; index < 16; index++) {
            if(offset + index < (int)size) {
                fprintf(fp, "%02x ", 0xff & src[offset + index]);
            } else {
                fprintf(fp, "   ");  /* Padding for incomplete lines */
            }
        }
        
        /* ASCII representation column */
        fprintf(fp, "| ");
        for(index = 0; index < 16; index++) {
            if(offset + index < (int)size) {
                if(isascii(src[offset + index]) && isprint(src[offset + index])) {
                    fprintf(fp, "%c", src[offset + index]);
                } else {
                    fprintf(fp, ".");  /* Non-printable character */
                }
            } else {
                fprintf(fp, " ");  /* Padding for incomplete lines */
            }
        }
        fprintf(fp, " |\n");
    }
    
    /* Print footer */
    fprintf(fp, "+------+-------------------------------------------------+------------------+\n");
    funlockfile(fp);
}

/* ============================================================================
 * Queue Implementation
 * ============================================================================

/**
 * @brief Queue entry structure
 */
struct queue_entry {
    struct queue_entry *next;  /* Next entry in queue */
    void *data;               /* User data pointer */
};

/**
 * @brief Initialize queue structure
 * @param queue Queue to initialize
 */
void queue_init(struct queue_head *queue)
{
    queue->head = NULL;
    queue->tail = NULL;
    queue->num = 0;
}

/**
 * @brief Push data onto queue
 * @param queue Queue to push to
 * @param data Data to push
 * @return Data pointer on success, NULL on failure
 */
void *queue_push(struct queue_head *queue, void *data)
{
    struct queue_entry *entry;

    if (!queue) {
        return NULL;
    }
    
    /* Allocate new queue entry */
    entry = memory_alloc(sizeof(*entry));
    if (!entry) {
        return NULL;
    }
    
    /* Initialize entry */
    entry->next = NULL;
    entry->data = data;
    
    /* Add to end of queue */
    if (queue->tail) {
        queue->tail->next = entry;
    }
    queue->tail = entry;
    if (!queue->head) {
        queue->head = entry;
    }
    queue->num++;
    return data;
}

/**
 * @brief Pop data from queue
 * @param queue Queue to pop from
 * @return Data pointer, NULL if queue is empty
 */
void *queue_pop(struct queue_head *queue)
{
    struct queue_entry *entry;
    void *data;

    if (!queue || !queue->head) {
        return NULL;
    }
    
    /* Remove from front of queue */
    entry = queue->head;
    queue->head = entry->next;
    if (!queue->head) {
        queue->tail = NULL;
    }
    queue->num--;
    
    /* Extract data and free entry */
    data = entry->data;
    memory_free(entry);
    return data;
}

/**
 * @brief Peek at front of queue without removing
 * @param queue Queue to peek at
 * @return Data pointer at front, NULL if queue is empty
 */
void *queue_peek(struct queue_head *queue)
{
    if (!queue || !queue->head) {
        return NULL;
    }
    return queue->head->data;
}

/**
 * @brief Iterate over all queue entries
 * @param queue Queue to iterate over
 * @param func Callback function for each entry
 * @param arg User argument passed to callback
 */
void queue_foreach(struct queue_head *queue, void (*func)(void *arg, void *data), void *arg)
{
    struct queue_entry *entry;

    if (!queue || !func) {
        return;
    }
    
    /* Iterate through all entries */
    for (entry = queue->head; entry; entry = entry->next) {
        func(arg, entry->data);
    }
}

/* ============================================================================
 * Byte Order Conversion
 * ============================================================================

/* Endianness constants */
#ifndef __BIG_ENDIAN
#define __BIG_ENDIAN 4321
#endif
#ifndef __LITTLE_ENDIAN
#define __LITTLE_ENDIAN 1234
#endif

/* Runtime endianness detection */
static int endian;

/**
 * @brief Detect system byte order at runtime
 * @return __LITTLE_ENDIAN or __BIG_ENDIAN
 */
static int byteorder(void)
{
    uint32_t x = 0x00000001;
    return *(uint8_t *)&x ? __LITTLE_ENDIAN : __BIG_ENDIAN;
}

/**
 * @brief Swap bytes in 16-bit value
 * @param v 16-bit value to swap
 * @return Byte-swapped value
 */
static uint16_t byteswap16(uint16_t v)
{
    return (v & 0x00ff) << 8 | (v & 0xff00) >> 8;
}

/**
 * @brief Swap bytes in 32-bit value
 * @param v 32-bit value to swap
 * @return Byte-swapped value
 */
static uint32_t byteswap32(uint32_t v)
{
    return (v & 0x000000ff) << 24 | (v & 0x0000ff00) << 8 | 
           (v & 0x00ff0000) >> 8 | (v & 0xff000000) >> 24;
}

/**
 * @brief Convert 16-bit value from host to network byte order
 * @param h 16-bit value in host byte order
 * @return Value in network byte order (big-endian)
 */
uint16_t hton16(uint16_t h)
{
    if (!endian) {
        endian = byteorder();
    }
    return endian == __LITTLE_ENDIAN ? byteswap16(h) : h;
}

/**
 * @brief Convert 16-bit value from network to host byte order
 * @param n 16-bit value in network byte order
 * @return Value in host byte order
 */
uint16_t ntoh16(uint16_t n)
{
    if (!endian) {
        endian = byteorder();
    }
    return endian == __LITTLE_ENDIAN ? byteswap16(n) : n;
}

/**
 * @brief Convert 32-bit value from host to network byte order
 * @param h 32-bit value in host byte order
 * @return Value in network byte order (big-endian)
 */
uint32_t hton32(uint32_t h)
{
    if (!endian) {
        endian = byteorder();
    }
    return endian == __LITTLE_ENDIAN ? byteswap32(h) : h;
}

/**
 * @brief Convert 32-bit value from network to host byte order
 * @param n 32-bit value in network byte order
 * @return Value in host byte order
 */
uint32_t ntoh32(uint32_t n)
{
    if (!endian) {
        endian = byteorder();
    }
    return endian == __LITTLE_ENDIAN ? byteswap32(n) : n;
}

/* ============================================================================
 * Checksum Calculation
 * ============================================================================

/**
 * @brief Calculate 16-bit internet checksum (RFC 1071)
 * @param addr Data to checksum
 * @param count Number of bytes to checksum
 * @param init Initial checksum value (for incremental calculation)
 * @return 16-bit checksum in network byte order
 */
uint16_t cksum16(uint16_t *addr, uint16_t count, uint32_t init)
{
    uint32_t sum;

    sum = init;
    
    /* Sum 16-bit words */
    while (count > 1) {
        sum += *(addr++);
        count -= 2;
    }
    
    /* Add leftover byte if count is odd */
    if (count > 0) {
        sum += *(uint8_t *)addr;
    }
    
    /* Fold 32-bit sum to 16 bits */
    while (sum >> 16) {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    
    /* One's complement */
    return ~(uint16_t)sum;
}