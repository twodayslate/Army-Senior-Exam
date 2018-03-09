#include "common.h"
#include "plugins/icmp.h"

#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
//#include <linux/ip.h>
#include <netdb.h>
#include <linux/if_packet.h>
#include <unistd.h>
#include<netinet/if_ether.h>  //For ETH_P_ALL
#include <netinet/ip_icmp.h> // for _update_icmp_checksum

// http://www.pdbuchan.com/rawsock/rawsock.html

static char *lastError = "";
static int lastSocket = -1;

/** given function 
 * calculate and set the checksum for an ITP message
 */
static void _update_icmp_checksum(unsigned short *ptr, int nbytes) {
    long sum;
    unsigned short oddbyte;
    unsigned short answer;
    struct icmphdr *icmph = (struct icmphdr *) ptr;
    
    sum = 0;
    
    while(nbytes > 1) {
        sum += *ptr++;
        nbytes -= 2;
    }
    
    if(nbytes == 1) {
        oddbyte = 0 ;
        *((unsigned char *) & oddbyte) = *(unsigned char *)ptr;
        sum += oddbyte;
    }
    
    sum = (sum >> 16) + (sum & 0xffff);
    sum += (sum >> 16);
    answer = ~sum;
    icmph->checksum = answer;
}

/** print the latest error */
void plugin_perror(const char * msg) {
    printf("%s: %s\n", msg, lastError);
}

/** get the latest socket */
int plugin_socket() {
    if(lastSocket > 0) {
        return lastSocket;
    }
    // https://stackoverflow.com/questions/47122298/sendto-invalid-argument-raw-socket
    // https://stackoverflow.com/questions/1637835/packet-sniffing-using-raw-sockets-in-linux-in-c
    // only see ip packets
    lastSocket = socket(AF_INET, SOCK_RAW, htons(ETH_P_IP));
    
    if(lastSocket < 0) {
        lastError = strerror(errno);
    } else {
        // https://stackoverflow.com/questions/24194961/how-do-i-use-setsockoptso-reuseaddr
        int reuse = 1;
        if (setsockopt(lastSocket, SOL_SOCKET, SO_REUSEADDR, (const char*)&reuse, sizeof(reuse)) < 0) {
            perror("setsockopt(SO_REUSEADDR) failed");
        }
        
        // this would be necessary for raw raw packets since we would have to create our own IP hdr and stuff
        // we are having the kernel do that stuff for us instead
//         int on = 1;
//         if (setsockopt(lastSocket, IPPROTO_IP, IP_HDRINCL, &on, sizeof(on)) < 0) {
//             perror("setsockopt(IP_HDRINCL) failed");
//         }

    }
   
    return lastSocket;
}

/** 
 * calculate the total size of an itp message
 * @returns the total size of the itp message
 */
uint16_t calc_packet_size(const struct itp *packet) {
    printd("calc_packet_size(...): %d %d %d\n", (int) sizeof(struct itphdr), (int) sizeof(uint16_t), (int) packet->payload_size);
    return sizeof(struct itphdr) + sizeof(uint16_t) + packet->payload_size;
}

/**
 * Generate an ITP message
 * @param len: the size of the data; on return will have the remaining size
 * @param remDatptr: if the length of data does not fit inside an ITP message 
 *                   then this will point to the remaining data
 * @returns itp message
 */
struct itp genMessage(const char *data, size_t *len, enum itp_type type, enum itp_generic_mode mode, char *remDataPtr) {
    struct itp msg = {
      .hdr.type = type,
      .hdr.code = 0,
      .hdr.checksum = 0,
    };
    
    switch(mode) {
        case ITP_MODE_REQUEST:
            msg.hdr.mode_one = ITP_MODE_ONE_REQUEST;
            msg.hdr.mode_two = ITP_MODE_TWO_REQUEST;
            break;
        case ITP_MODE_REPLY:
            msg.hdr.mode_one = ITP_MODE_ONE_REPLY;
            msg.hdr.mode_two = ITP_MODE_TWO_REPLY;
            break;
        case ITP_MODE_END:
            msg.hdr.mode_one = ITP_MODE_ONE_END;
            msg.hdr.mode_two = ITP_MODE_TWO_END;
            break;
        default:
            msg.hdr.mode_one = ITP_MODE_ONE_ERR;
            msg.hdr.mode_two = ITP_MODE_TWO_ERR;
            break;
    };
    
    size_t psize = MAX(*len, ITP_MAX_PAYLOAD_SIZE);
    
    msg.payload_size = psize;
    
    if(data != NULL) {
        memcpy(msg.payload, data, psize);
        remDataPtr = (char *)data + psize;
        *len = MAX(*len - psize, 0);
    } else {
        remDataPtr = NULL;
    }
    
    _update_icmp_checksum((unsigned short *) &msg, calc_packet_size(&msg));
    return msg;
} 

/** A wrapper for `genMessage` that will return a general REQUEST messages */
struct itp genRequestMessage(const char *data, size_t *len, char *remDataPtr) {
    return genMessage(data, len, ITP_TYPE_REQUEST, ITP_MODE_REQUEST, remDataPtr);
}

/** A wrapper for `genMessage` that will return a general REPLY message */
struct itp genReplyMessage(const char *data, size_t *len, char *remDataPtr) {
    return genMessage(data, len, ITP_TYPE_REPLY, ITP_MODE_REPLY, remDataPtr);
}

/** A wrapper for `genMesssage` that will return an ERR(OR) message with the given error string */
struct itp genErrorMessage(const char *msg, enum itp_type type) {
    size_t len = MAX(strlen(msg), ITP_MAX_PAYLOAD_SIZE);
    struct itp retVal = genMessage(msg, &len,type, ITP_MODE_ERR, NULL);
    strcpy(retVal.payload, msg);
    return retVal;
}

/**
 * @returns the total amount of data bytes sent or -1 on error
 */
ssize_t plugin_sendto(int sockfd, const void *buf, size_t len, int flags,
                       const struct sockaddr *dest_addr, socklen_t addrlen) {
    printlnd("sendto(...) %s...", inet_ntoa(((struct sockaddr_in *)dest_addr)->sin_addr));
    // https://stackoverflow.com/questions/13620607/creating-ip-network-packets#13620771
    size_t sentLen = 0;
    while(sentLen < len) {
        struct itp msg;
        
        switch((PLUGIN_MSG_TYPE) flags) {
            case PLUGIN_MSG_REQUEST:
                msg.hdr.type = ITP_TYPE_REQUEST;
                msg.hdr.mode_one = ITP_MODE_ONE_REQUEST;
                msg.hdr.mode_two = ITP_MODE_TWO_REQUEST;
                break;
            case PLUGIN_MSG_REQUEST_DONE:
                msg.hdr.type = ITP_TYPE_REQUEST;
                msg.hdr.mode_one = ITP_MODE_ONE_END;
                msg.hdr.mode_two = ITP_MODE_TWO_END;
                break;
            case PLUGIN_MSG_REPLY:
                msg.hdr.type = ITP_TYPE_REPLY;
                msg.hdr.mode_one = ITP_MODE_ONE_REPLY;
                msg.hdr.mode_two = ITP_MODE_TWO_REPLY;
                break;
            case PLUGIN_MSG_REPLY_DONE:
                msg.hdr.type = ITP_TYPE_REPLY;
                msg.hdr.mode_one = ITP_MODE_ONE_END;
                msg.hdr.mode_two = ITP_MODE_TWO_END;
                break;
            case PLUGIN_MSG_REPLY_ERR:
            case PLUGIN_MSG_REPLY_FRAG:
                msg.hdr.type = ITP_TYPE_REPLY;
                msg.hdr.mode_one = ITP_MODE_ONE_ERR;
                msg.hdr.mode_two = ITP_MODE_TWO_ERR;
                break;
            default:
                return -1;
        };
        msg.hdr.checksum = 0;
        msg.hdr.code = 0;
        size_t toCpy = MIN(MAX(len - sentLen,0), ITP_MAX_PAYLOAD_SIZE);
        msg.payload_size = toCpy;
        memcpy(msg.payload, buf + sentLen, toCpy);
        _update_icmp_checksum((unsigned short *) &msg, calc_packet_size(&msg));
        
        printlnd("Sending %d/%d   %d", (int) toCpy, (int) len, (int) sentLen);
        
        printd("Planning to send %d\n", (int) calc_packet_size(&msg));
        
        ssize_t retVal = sendto(sockfd, &msg, calc_packet_size(&msg), MSG_CONFIRM, dest_addr, addrlen);
        if(retVal < 0) {
            lastError = strerror(errno);
            break;
        }
        sentLen = sentLen + toCpy;
    }
    if(sentLen >= len) {
        printlnd("gonna send an _END");
        if( ((PLUGIN_MSG_TYPE) flags) == PLUGIN_MSG_REPLY || ((PLUGIN_MSG_TYPE) flags) == PLUGIN_MSG_REQUEST) {
            struct itp msg;
            switch((PLUGIN_MSG_TYPE) flags) {
                case PLUGIN_MSG_REQUEST:
                case PLUGIN_MSG_REQUEST_DONE:
                    printlnd("Sending REQUEST _END");
                    msg.hdr.type = ITP_TYPE_REQUEST;
                    break;
                case PLUGIN_MSG_REPLY:
                case PLUGIN_MSG_REPLY_DONE:
                case PLUGIN_MSG_REPLY_ERR:
                case PLUGIN_MSG_REPLY_FRAG:
                    printlnd("Sending REPLY _END");
                    msg.hdr.type = ITP_TYPE_REPLY;
                    break;
                default:
                    return -1;
            };
            msg.hdr.checksum = 0;
            msg.hdr.code = 0;
            msg.hdr.mode_one = ITP_MODE_ONE_END;
            msg.hdr.mode_two = ITP_MODE_TWO_END;
            msg.payload_size = 0;
            _update_icmp_checksum((unsigned short *) &msg, calc_packet_size(&msg));
            ssize_t retVal = sendto(sockfd, &msg, calc_packet_size(&msg), MSG_CONFIRM, dest_addr, addrlen);
            if(retVal < 0) {
                lastError = strerror(errno);
                return -1;
            }
        }
    }
    
    return sentLen;
}

/** returns true if the given data is a valid ITP message */
bool is_our_icmp(struct itp *msg, size_t size) {
    if (size <= sizeof(struct itphdr) + sizeof(struct iphdr)) {
        return false;
    }
    
    printlnd("is_itp(...): size check complete %d", msg->hdr.type);
    
    if(msg->hdr.type != ITP_TYPE_REPLY && msg->hdr.type != ITP_TYPE_REQUEST) {
        return false;
    }
    
    if(msg->hdr.code != 0) {
        return false;
    }
    
    printd("is_itp(...): is a reply or request\n");
    if(msg->hdr.mode_one != ITP_MODE_ONE_REQUEST &&
      msg->hdr.mode_one != ITP_MODE_ONE_REPLY &&
      msg->hdr.mode_one != ITP_MODE_ONE_ERR &&
      msg->hdr.mode_one != ITP_MODE_ONE_END) {
        return false;
    }
    
    if(msg->hdr.mode_two != ITP_MODE_TWO_REQUEST &&
      msg->hdr.mode_two != ITP_MODE_TWO_REPLY &&
      msg->hdr.mode_two != ITP_MODE_TWO_ERR &&
      msg->hdr.mode_two != ITP_MODE_TWO_END) {
        return false;
    }  
    
    return true;
}

/** returns true if the modes match each other (same generic) */
bool itp_modes_match(enum itp_mode_one one, enum itp_mode_two two) {
    if(one == ITP_MODE_ONE_REQUEST && two != ITP_MODE_TWO_REQUEST) {
        printlnd("mismatch on REQUEST");
        return false;
    }
    if(one == ITP_MODE_ONE_REPLY && two != ITP_MODE_TWO_REPLY) {
        printlnd("mismatch on REPLY");
        return false;
    }
    if(one == ITP_MODE_ONE_ERR && two != ITP_MODE_TWO_ERR) {
        printlnd("mismatch on ERR");
        return false;
    }
    if(one == ITP_MODE_ONE_END && two != ITP_MODE_TWO_END) {
        printlnd("mismatch on END");
        return false;
    }
    
    return true;
}

/** returns true if the given ITP message is of a given PLUGIN_MSG_TYPE */
bool is_of_type(struct itp *msg, PLUGIN_MSG_TYPE flag) {
    switch(flag) {
        case PLUGIN_MSG_REQUEST:
        case PLUGIN_MSG_REQUEST_DONE:
            printd("is a request\n");
            return msg->hdr.type == ITP_TYPE_REQUEST;
        case PLUGIN_MSG_REPLY:
        case PLUGIN_MSG_REPLY_ERR:
        case PLUGIN_MSG_REPLY_FRAG:
        case PLUGIN_MSG_REPLY_DONE:
            printd("is a reply %d\n", (int) msg->hdr.type == ITP_TYPE_REPLY);
            return msg->hdr.type == ITP_TYPE_REPLY;
        default:
            return false;
    };
}

/**
 * @param buf: a void *ptr to NULL - so actually a void**
 * @param len: unused
 * @returns: (ssize_t) the amount of data in buf, -1 on error
 */
ssize_t plugin_recvfrom(int sockfd, void *bufptr, size_t len, int flags, struct sockaddr *src_addr, socklen_t *addrlen) {
    struct ip_itp_packet msg;
    time_t timeout = time(NULL);
    ssize_t curBufSize = 0;
    printd("bufptr: %p\n", bufptr);
    void *buf = (void*)*((void**)bufptr);
     printd("buf: %p\n",buf);
    while(true) {
        ssize_t retVal = recvfrom(sockfd, &msg, sizeof(struct ip_itp_packet), MSG_DONTWAIT, src_addr, addrlen);
        if(retVal >= 0) {
            #ifdef DEBUG
            struct sockaddr_in *mysa = (struct sockaddr_in *) src_addr;
            printlnd("recvfrom ip_src %s ret %d...", inet_ntoa(mysa->sin_addr), (int) retVal);
            #endif
            
            timeout = time(NULL);
            
            if(retVal >= sizeof(struct iphdr) + sizeof(struct itphdr) + sizeof(uint16_t)) {
                printlnd("%s", (char *) msg.data.payload);
                if(is_our_icmp(&(msg.data), retVal)) {
                    printlnd("is our icmp");
                    if( is_of_type(&(msg.data), (PLUGIN_MSG_TYPE)flags) ) {
                        printd("is our icmp packet type of total size %d with payload size %d\n", (int) retVal, msg.data.payload_size);
                        printd("payload of size %d\n------ start -----\n%s\n------- end -----\n", msg.data.payload_size, (char *) msg.data.payload);

                        if(!itp_modes_match(msg.data.hdr.mode_one, msg.data.hdr.mode_two)) {
                            printlnd("mismatch error");
                            // an error occured so break out and return NULL
                            if(buf != NULL && curBufSize > 0) {
                                free(buf);
                            }
                            lastError = "ITP mode mismatch or ITP error\n";
                            curBufSize = -1;
                            break;
                        }

                        if(msg.data.payload_size > ITP_MAX_PAYLOAD_SIZE) {
                            printlnd("max size error");
                            if(buf != NULL && curBufSize > 0) {
                                free(buf);
                            }
                            lastError = "ITP max size error\n";
                            curBufSize = -1;
                            break;
                        }

                        if(retVal > sizeof(struct ip_itp_packet)) {
                            printlnd("size error %d %d", (int) retVal, (int) sizeof(struct ip_itp_packet));
                            if(buf != NULL && curBufSize > 0) {
                                free(buf);
                            }
                            lastError = "ITP size error\n";
                            curBufSize = -1;
                            break;
                        }
                        uint8_t checksum = msg.data.hdr.checksum;
                        msg.data.hdr.checksum = 0;
                        _update_icmp_checksum((unsigned short *) &(msg.data), calc_packet_size(&(msg.data)));
                        printlnd("checksum %d v %d", checksum, msg.data.hdr.checksum);
                        
                        if(checksum != msg.data.hdr.checksum) {
                            lastError = "Checksum mismatch\n";
                            curBufSize = -1;
                            break;
                        }

                        printlnd("allocating buf %p of size %d", buf, (int) (msg.data.payload_size + curBufSize));
                        void *tmpBuf = calloc(msg.data.payload_size + curBufSize, 1);
                        if(tmpBuf != NULL) {
                            if(buf != NULL && curBufSize > 0) {
                                memcpy(tmpBuf, (void*)*((void**)bufptr), curBufSize);
                                free(buf);
                            }
                        } else {
                            if(buf != NULL) {
                                free(buf);
                            }
                            curBufSize = -1;
                            lastError = "Unable to allocate memory\n";
                            break;
                        }
                        *((void**)bufptr) = tmpBuf;
                        buf =  (void*)*((void**)bufptr);
                        printlnd("buf %d now equals tmpbuf %p %p %p", (int) curBufSize, buf, tmpBuf,  *((void**)bufptr));
                        memcpy(*((char**)bufptr) + curBufSize, msg.data.payload, msg.data.payload_size);
                        curBufSize = curBufSize + msg.data.payload_size;

                        if(itp_modes_match(msg.data.hdr.mode_one, msg.data.hdr.mode_two) && 
                            ((msg.data.hdr.mode_one == ITP_MODE_ONE_END) || (msg.data.hdr.mode_one == ITP_MODE_ONE_ERR))) {
                            // msg is done sending so ret the data stream
                            break;
                        } 
                    } else {
                        printlnd("is not our icmp type %x %x", msg.data.hdr.type, flags);
                    }
                }
            }
        } else {
            if(errno != EAGAIN && errno != EWOULDBLOCK) {
                lastError = strerror(errno);
                perror("recvfrom");
                if(buf != NULL && curBufSize > 0) {
                    free(buf);
                }
                curBufSize = -1;
                break;
            }
        }
        if(time(NULL) - timeout > ISH_TIMEOUT) { // 5 second timeout
            printlnd("hit timeout! %d %d %d", (int) time(NULL), (int) timeout, (int) (time(NULL)-timeout));
            printd("buf: %p\n", buf);
            lastError = "recvfrom timed out\n";
            if(buf != NULL && curBufSize > 0) {
                free(buf);
            }
            curBufSize = -1;
            break;
        }
    } // while

    if(curBufSize > 0) {
        printlnd("ret buf %d %s", (int) curBufSize, (char *)buf);
    } else {
        if((void*)*((void**)bufptr) != NULL) {
            free((void*)*((void**)bufptr));
        }
    }
    
    return curBufSize;
}

void plugin_debug() {
    printf("debug!\n");
}

struct fntable plugin_icmp_fntable = {
    .perror = plugin_perror,
    .socket = plugin_socket,
    .sendto = plugin_sendto,
    .recvfrom = plugin_recvfrom,
    #ifdef DEBUG
    .debug = plugin_debug
    #endif
};