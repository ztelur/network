#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>

#define MAXLINE 4096

int main(int argc, char** argv) {
    int listenfd, connfd;
    struct sockaddr_in servadrr;
    char buf[1024];
    int n;

    if ((listenfd = socket(AF_INET, SOCK_STREAM, 0)) == -1) {
        printf("create socket error: %s(errno: %d)\n",strerror(errno),errno);
        exit(0);
    }


    memset(&servadrr, 0, sizeof(servadrr));
    servadrr.sin_family = AF_INET;
    servadrr.sin_addr.s_addr = htonl(INADDR_ANY);
    servadrr.sin_port = htons(6666);

    if (bind(listenfd, (struct sockaddr*)&servadrr, sizeof(servadrr)) == -1) {
        printf("bind socket error: %s(errno: %d)\n",strerror(errno),errno);
        exit(0);
    }

    if (listen(listenfd, 10) == -1) {
        printf("listen socket error: %s(errno: %d)\n",strerror(errno),errno);
        exit(0);
    }

    printf("======waiting for client's request======\n");

    while (1) {
        if ((connfd = accept(listenfd, (struct sockaddr*) NULL, NULL)) == -1) {
            printf("accept socket error: %s(errno: %d)",strerror(errno),errno);
            continue;
        }
        n = recv(connfd, buf, MAXLINE, 0);
        buf[n] = '\0';
        printf("recv msg from client: %s\n", buf);
//        close(connfd);
    }

}