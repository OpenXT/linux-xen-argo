#ifndef __PROJECT_H__
# define __PROJECT_H__

# include "config.h"

# include <stdio.h>
# include <stdlib.h>
# include <stdint.h>
# include <stdarg.h>

# include <limits.h>

# include <errno.h>
# include <assert.h>

# include <string.h>
# include <strings.h>

# include <unistd.h>
# include <fcntl.h>

# include <getopt.h>

# include <sys/ioctl.h>
# include <sys/socket.h>
# include <linux/socket.h>
# include <linux/vm_sockets.h>

/*
 * Output macro helpers.
 */
static unsigned int __enable_debug_print = 0;
#define printd(fmt, ...)                                \
    do {                                                \
        if (__enable_debug_print)                       \
            fprintf(stderr, "debug:%s:%d: " fmt "\n",   \
                    __func__, __LINE__, ##__VA_ARGS__); \
    } while (0)
#define printi(fmt, ...) \
    fprintf(stdout, fmt "\n", ##__VA_ARGS__)
#define printw(fmt, ...) \
    fprintf(stderr, "warning: " fmt "\n", ##__VA_ARGS__)
#define printe(fmt, ...) \
    fprintf(stderr, "error: " fmt "\n", ##__VA_ARGS__)

/*
 * GCC macro helpers.
 */
#define unused(x) ((void)(x))

# include "utils.h"

#endif /* __PROJECT_H__ */
