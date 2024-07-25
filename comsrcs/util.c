#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <signal.h>
#include <sys/types.h>
#include <sys/stat.h>
#include "util.h"

char* bin2hex(unsigned char* bin, unsigned int len)
{
    const char hexchars[] = "0123456789ABCDEF";
    char* ret = NULL;
    int i = 0;

    ret = (char*)calloc(1, len * 2 + 1);
    if (ret == NULL) {
        return NULL;
    }

    for (i = 0; i < len; i++) {
        ret[i * 2] = hexchars[(bin[i] >> 4) & 0x0F];
        ret[i * 2 + 1] = hexchars[bin[i] & 0x0F];
    }

    ret[len * 2] = '\0';
    return ret;
}

void daemonize()
{
    pid_t pid = 0;

    pid = fork();
    if (pid < 0) {
        exit(EXIT_FAILURE);
    } else if (pid > 0) {
        exit(EXIT_SUCCESS);
    }

    if (setsid() < 0)
        exit(EXIT_FAILURE);

    signal(SIGCHLD, SIG_IGN);
    signal(SIGHUP, SIG_IGN);

    pid = fork();
    if (pid < 0) {
        exit(EXIT_FAILURE);
    } else if (pid > 0) {
        exit(EXIT_SUCCESS);
    }

    umask(0);
    chdir("/");

    close(STDIN_FILENO);
    close(STDOUT_FILENO);
    close(STDERR_FILENO);
    open("/dev/null", O_RDONLY);
    open("/dev/null", O_WRONLY);
    open("/dev/null", O_RDWR);

    return;
}

int file_write_content(const char* path, unsigned char* in, int inlen)
{
    int ret = 0;
    FILE* fp = NULL;

    fp = fopen(path, "wb");
    if(!fp) {
        log_e("save %s failed", path);
        return -1;
    }

    ret = fwrite(in, 1, inlen, fp);
    fclose(fp);
    return ret;
}