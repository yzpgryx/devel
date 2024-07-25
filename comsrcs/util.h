#ifndef __UTIL_H__
#define __UTIL_H__

#ifdef __cplusplus
extern "C" {
#endif

#include <syslog.h>

#define log_e(fmt, ...) \
    do { \
        syslog(LOG_ERR, fmt"\n", ##__VA_ARGS__); \
    } while(0)

#define log_i(fmt, ...) \
    do { \
        syslog(LOG_INFO, fmt"\n", ##__VA_ARGS__); \
    } while(0)

#define log_d(fmt, ...) \
    do { \
        syslog(LOG_DEBUG, fmt"\n", ##__VA_ARGS__); \
    } while(0)

#define SAFE_FREE(x) \
    do { \
        if(x) { \
            free(x); \
            x = NULL; \
        } \
    } while(0)

#define SAFE_FREE_EX(x, free_func) \
    do { \
    	if(x && free_func) { \
    		free_func(x); \
    		x = NULL; \
    	} \
    } while(0)

// process
void daemonize();

// strings
char* bin2hex(unsigned char* bin, unsigned int len);

// file
int file_write_content(const char* path, unsigned char* in, int inlen);

#ifdef __cplusplus
}
#endif

#endif