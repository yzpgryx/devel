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

unsigned char hex_to_byte(char hex_char) {
    static unsigned char hex_table[] = {
        ['0'] = 0x0, ['1'] = 0x1, ['2'] = 0x2, ['3'] = 0x3,
        ['4'] = 0x4, ['5'] = 0x5, ['6'] = 0x6, ['7'] = 0x7,
        ['8'] = 0x8, ['9'] = 0x9, ['a'] = 0xa, ['b'] = 0xb,
        ['c'] = 0xc, ['d'] = 0xd, ['e'] = 0xe, ['f'] = 0xf,
        ['A'] = 0xa, ['B'] = 0xb, ['C'] = 0xc, ['D'] = 0xd,
        ['E'] = 0xe, ['F'] = 0xf
    };
    return hex_table[(unsigned char)hex_char];
}

unsigned char* hex2bin(const char* hexstr, unsigned int* len) {
    int hex_len = strlen(hexstr);

    if (hex_len % 2 != 0) {
        *len = 0;
        return NULL;
    }

    *len = hex_len / 2;
    unsigned char* bin = (unsigned char*)malloc(*len);

    if (bin == NULL) {
        *len = 0;
        return NULL;
    }

    for (int i = 0; i < *len; i++) {
        bin[i] = (hex_to_byte(hexstr[2 * i]) << 4) | hex_to_byte(hexstr[2 * i + 1]);
    }

    return bin;
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

unsigned char* file_read_content(const char* path, unsigned int* len)
{
    FILE* fp = NULL;
    long size = 0;
    unsigned char* ret = NULL;

    fp = fopen(path, "rb");
    if(!fp) {
        log_e("read %s failed", path);
        return NULL;
    }

    fseek(fp, 0, SEEK_END);
    size = ftell(fp);

    ret = calloc(1, size);
    if(!ret) {
        goto exit;
    }

    fseek(fp, 0, SEEK_SET);
    *len = fread(ret, 1, size, fp);

exit:
    fclose(fp);
    return ret;
}