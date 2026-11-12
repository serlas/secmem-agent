#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main(int argc, char **argv) {
    if (argc < 2) { printf("secmemctl put key=value --ttl 10m\n"); exit(1); }

    int sock = socket(AF_UNIX, SOCK_STREAM, 0);
    struct sockaddr_un addr = {AF_UNIX, "/run/secmem.sock"};
    connect(sock, (struct sockaddr*)&addr, sizeof(addr));

    char buf[1024] = {0};
    strcat(buf, argv[1]);
    for (int i = 2; i < argc; i++) {
        strcat(buf, " ");
        strcat(buf, argv[i]);
    }
    write(sock, buf, strlen(buf));

    // Recv FD
    struct msghdr msg = {0};
    struct iovec iov = {0};
    char cmsg[CMSG_SPACE(sizeof(int))];
    msg.msg_control = cmsg;
    msg.msg_controllen = sizeof(cmsg);
    recvmsg(sock, &msg, 0);
    struct cmsghdr *cmsg_hdr = CMSG_FIRSTHDR(&msg);
    if (cmsg_hdr->cmsg_type == SCM_RIGHTS) {
        int fd = *((int*)CMSG_DATA(cmsg_hdr));
        char read_buf[1024] = {0};
        read(fd, read_buf, sizeof(read_buf));
        printf("%s\n", read_buf);
        close(fd);
    }

    close(sock);
    return 0;
}