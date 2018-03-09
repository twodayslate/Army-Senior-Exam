#ifndef __ICMP
#define __ICMP

#include "plugin.h"
#include <stdint.h>
#include <netinet/ip.h>

typedef enum itp_type {
    ITP_TYPE_REPLY = 0,
    ITP_TYPE_REQUEST = 8,
} ITP_Type;

enum itp_generic_mode {
    ITP_MODE_REQUEST,
    ITP_MODE_REPLY,
    ITP_MODE_ERR,
    ITP_MODE_END,
};

typedef enum itp_mode_one {
    ITP_MODE_ONE_REQUEST = 0xd000,
    ITP_MODE_ONE_REPLY = 0xdead,
    ITP_MODE_ONE_ERR = 0xbaad,
    ITP_MODE_ONE_END = 0xfeed,
} ITP_Mode_One;

typedef enum itp_mode_two {
    ITP_MODE_TWO_REQUEST = 0x000d,
    ITP_MODE_TWO_REPLY = 0xdeef,
    ITP_MODE_TWO_ERR = 0xf00d,
    ITP_MODE_TWO_END = 0xface,
} ITP_Mode_Two;

struct itphdr {
    uint8_t type; //8
    uint8_t code; //8
    uint8_t checksum; // 16
    uint16_t mode_one; // 16
    uint16_t mode_two; // 16
};

/** the maximum number of bytes an ITP payload can be */
#define ITP_MAX_PAYLOAD_SIZE 452-sizeof(uint16_t)

struct itp {
    struct itphdr hdr;
    uint16_t payload_size;
    char payload[ITP_MAX_PAYLOAD_SIZE];
};

struct ip_itp_packet {
    struct iphdr iphdr; // i couldn't get struct ip to import properly on my system so this is the second best alternative
    struct itp data;
};


void plugin_debug();
int plugin_socket();
void plugin_perror(const char * msg);
ssize_t plugin_sendto(int sockfd, const void *buf, size_t len, int flags, const struct sockaddr *dest_addr, socklen_t addrlen);
ssize_t plugin_recvfrom(int sockfd, void *buf, size_t len, int flags, struct sockaddr *src_addr, socklen_t *addrlen);

#endif