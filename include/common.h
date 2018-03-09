#ifndef __COMMMON
#define __COMMON

#include <stdio.h>
#include <stdarg.h>
#include <string.h>
#include <stdlib.h>
#include <stdbool.h>
#include <errno.h>
#include <unistd.h> // for close
#include <time.h>

#ifdef DEBUG
    #define printd(fmt, ...) do {\
        printf("%s@%s:%d: " fmt, __FILE__, __func__, __LINE__, ##__VA_ARGS__); \
    } while(0)
#else
    #define printd(fmt, ...) {}
#endif

#define printlnd(fmt, ...) do { printd(fmt "\n", ##__VA_ARGS__); } while(0)

#define ISH_DEFAULT_PORT 8788
#ifndef ISH_TIMEOUT
#define ISH_TIMEOUT 10
#endif
#define MAX(x, y) ((x) > (y) ? (x) : (y))
#define MIN(x, y) ((x) < (y) ? (x) : (y))
#endif
