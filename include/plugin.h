#ifndef __PLUGIN
#define __PLUGIN

#include "common.h"
#include <dlfcn.h> // for dlerror
#include <sys/socket.h>

typedef enum _PLUGIN_MSG_TYPE {
    PLUGIN_MSG_REQUEST,
    PLUGIN_MSG_REQUEST_DONE,
    PLUGIN_MSG_REPLY,
    PLUGIN_MSG_REPLY_ERR,
    PLUGIN_MSG_REPLY_FRAG,
    PLUGIN_MSG_REPLY_DONE,
} PLUGIN_MSG_TYPE;

struct fntable {
    void (*perror) (const char *s);
    int (*socket) (void);
    ssize_t (*sendto) (int sockfd, const void *buf, size_t len, int flags,
                       const struct sockaddr *dest_addr, socklen_t addrlen);
    ssize_t (*recvfrom) (int sockfd, void *buf, size_t len, int flags, struct sockaddr *src_addr, socklen_t *addrlen);
    #ifdef DEBUG
    void (*debug)();
    #endif
};

const char *DEFAULT_FNTABLE_SYMBOL_NAME;
struct fntable *plugin_load_default(const char *filename);
struct fntable *plugin_load(const char *filename, const char *fntable_symbol_name);
void plugin_unload(void);

#endif