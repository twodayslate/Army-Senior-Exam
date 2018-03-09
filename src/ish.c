#include "common.h"
#include "plugin.h"

#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h> 

void do_help() {
    printf("usage: ish [options] ip command...\n");
    printf("\n");
    printf("Options:\n");
    printf("\t-h, --help    show this message and exit\n");
}

void printbuf(char *buf, size_t size) {
    for(int i = 0; i < size; i++) {
        printf("%c", buf[i]);
    }
}

int main(int argc, char *argv[]) {
    #ifdef DEBUG
    char* test = "testing";
    printlnd("Launching ish %d %d %s", (int) sizeof(void*), (int) sizeof(char), test+2);
    #endif
    

    
    for(int i = 1; i < argc; i++) {
        if ((strncmp(argv[i], "-h", 2) == 0) || (strncmp(argv[i], "--help", 6) == 0)) {
            do_help();
            return 0;
        }
    }
    
    if(argc < 3) {
        printf("Not enough arguments\n\n");
        do_help();
        return -1;
    }
    
    struct fntable *table = plugin_load("./bin/plugin-icmp.so", "plugin_icmp_fntable");
    if(table == NULL) {
        printf("Should be in ./bin/plugin-icmp.so");
        printf("Failed to load plugin\n%s\n", dlerror());
        return -1;
    }
    #ifdef ISH_DEBUG
        table->debug();
    #endif
    
    int sockfd;
    struct hostent *server;
    struct sockaddr_in sockaddr;
    char *args = NULL;
    
    server = gethostbyname(argv[1]);
    if(server == NULL) {
        printf("Unable to get host by name\n");
        plugin_unload();
        return -1;
    }
    
    if(server->h_length <= 0 || server->h_addr_list[0] == NULL) {
        printf("Unable to get host by name\n");
        plugin_unload();
        return -1;
    }
    
    sockfd = table->socket();
    if(sockfd < 0) {
        table->perror("Error opening socket");
        return -1;
    }
    
    size_t argSize = 0;
    for(int i = 2; i < argc; i++) {
        //printlnd("arg %d %s %d", i, argv[i], (int) strlen(argv[i]));
        argSize += strlen(argv[i]) + 1; // + 1 for spaces
    }
    printlnd("arg size: %d", (int) argSize);
    args = (char *) calloc(argSize, 1);
    if(args != NULL) {
        strcat(args, argv[2]);
        for(int i = 3; i < argc; i++) {
            strcat(args, " ");
            strcat(args, argv[i]);
        }
    } else {
        goto fail;
    }
    
    bool didRun = false;
    
    for(int i = 0; i < server->h_length; i++) {
        didRun = false;
        sockaddr.sin_addr = *(struct in_addr *) server->h_addr_list[i];
    
        char *addrName = inet_ntoa(sockaddr.sin_addr);

        printlnd("Connecting to %s (%s)...", addrName, server->h_name);

        sockaddr.sin_family = server->h_addrtype;
        
        if(server->h_addrtype != AF_INET) {
            printd("not AF_INET");
            continue;
        }

        if( connect(sockfd, (struct sockaddr*) &sockaddr, sizeof(sockaddr)) < 0) {
            printf("Failed to connect to server!\n\t%s\n", addrName);
            continue;
        }

        printlnd("args given = \"%s\"", args);

        //table->sendto(sockfd, args, argSize, MSG_CONFIRM, (struct sockaddr*) &sockaddr, sizeof(sockaddr));
        ssize_t retVal = table->sendto(sockfd, args, argSize, PLUGIN_MSG_REQUEST, (struct sockaddr*) &sockaddr, sizeof(sockaddr));
        if(retVal <= 0) {
            printd("Failed to send\n");
            table->perror("Failed to send");
            continue;
        }
        didRun = true;
        time_t timeout = time(NULL);
        while(true) {
            void *buf = NULL;
            socklen_t peer_addr_len = sizeof(sockaddr);
            retVal = table->recvfrom(sockfd, (void*)&buf, 0, PLUGIN_MSG_REPLY, (struct sockaddr *) &sockaddr, &peer_addr_len);
            if(retVal > 0) {
                printlnd("retVal = %i", (int) retVal);
                printbuf(buf, retVal);
                free(buf);
                break;
            }
             if(time(NULL) - timeout > ISH_TIMEOUT) {
                 printf("Request timeout\n");
                 break;
             }
        }
        if(didRun) {
            break;
        }
    }
   
    if(!didRun) {
        printd("Never ran!\n");
    }
    
fail:    
    if(args != NULL) {
        free(args);
    }
    close(sockfd);
    plugin_unload();
    
    printd("Closing ish.\n");
    return 0;
}