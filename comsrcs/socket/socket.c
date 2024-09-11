#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include "util.h"

static int socket_setup(const char* ip, int port)
{
    int sockfd;
    struct sockaddr_in server_addr;

    if ((sockfd = socket(AF_INET, SOCK_STREAM, 0)) == -1) {
        log_e("socket failed");
        return -1;
    }

    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(port);
    server_addr.sin_addr.s_addr = inet_addr(ip);
    memset(&(server_addr.sin_zero), '\0', 8);

    if (bind(sockfd, (struct sockaddr *)&server_addr, sizeof(struct sockaddr)) == -1) {
        log_e("bind error");
        close(sockfd);
        return -1;
    }

    if (listen(sockfd, 1024) == -1) {
        log_e("listen error");
        close(sockfd);
        return -1;
    }

    log_d("qauthd listening on %s:%d", ip, port);
    return sockfd;
}

static int wait_connect(int sockfd)
{
    struct sockaddr_in client_addr;
    char client_ip[INET_ADDRSTRLEN];
    socklen_t sin_size;
    int fd = 0;

    sin_size = sizeof(struct sockaddr_in);
    if ((fd = accept(sockfd, (struct sockaddr *)&client_addr, &sin_size)) == -1) {
        log_e("accept error");
        close(sockfd);
        return -1;
    }

    inet_ntop(AF_INET, &(client_addr.sin_addr), client_ip, INET_ADDRSTRLEN);
    log_d("Got connection from %s:%d", client_ip, ntohs(client_addr.sin_port));

    return fd;
}

static int iwrite(int fd, unsigned char* data, int len)
{
    int bytes_sent = 0, total_sent = 0, bytes_left = len;

    while (total_sent < len) {
        bytes_sent = write(fd, data + total_sent, bytes_left);
        if (bytes_sent < 0) {
            log_e("write error");
            break;
        }
        total_sent += bytes_sent;
        bytes_left -= bytes_sent;
    }

    return total_sent;
}

static int iread(int fd, unsigned char** out)
{
    fd_set read_fds;
    struct timeval timeout;
    ssize_t bytes_read;
    int ret = 0, bytes_available = 0;
    unsigned char* buffer = NULL;

    FD_ZERO(&read_fds);
    FD_SET(fd, &read_fds);

    timeout.tv_sec = 10;
    timeout.tv_usec = 0;

    ret = select(fd + 1, &read_fds, NULL, NULL, &timeout);
    if (ret < 0) {
        log_e("select error");
        return -1;
    } else if (ret == 0) {
        log_e("timeout, no data to read");
        return -1;
    } else {
        if (FD_ISSET(fd, &read_fds)) {
            if (ioctl(fd, FIONREAD, &bytes_available) < 0) {
                log_e("ioctl error");
                return -1;
            }

            buffer = calloc(1, bytes_available);
            if(!buffer) {
                log_e("allocate %d bytes out of memory", bytes_available);
                return -1;
            }

            bytes_read = read(fd, buffer, bytes_available);
            if (bytes_read <= 0) {
                log_e("read error");
                free(buffer);
                return -1;
            }

            *out = buffer;
        }
    }

    return bytes_read;
}

int main(int argc, char* const argv[])
{

}