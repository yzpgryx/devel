#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <getopt.h>
#include <signal.h>
#include "util.h"

#define BUFFER_SIZE 1024
#define DAEMON_VERSION "1.0.0"

const struct option long_options[] = {
    {"help", no_argument, NULL, 'h'},
    {"version", no_argument, NULL, 'v'},
    {"background", no_argument, NULL, 'b'},
    {"log", required_argument, NULL, 'l'},
    {"config", required_argument, NULL, 1}
};

typedef struct {
    int background;
    int loglevel;
} daemon_opts_t;
static daemon_opts_t opts;

static void handle_signal(int sig)
{
    switch (sig)
    {
    case SIGTERM:
        syslog(LOG_NOTICE, "Received SIGTERM signal.");
        exit(EXIT_SUCCESS);
        break;
    default:
        syslog(LOG_WARNING, "Unhandled signal (%d) %s.", sig, strsignal(sig));
        break;
    }
}

void load_config(const char *filename, daemon_opts_t* opts) {
    FILE* fp = NULL;
    char line[BUFFER_SIZE] = {0};
    char key[BUFFER_SIZE] = {0}, value[BUFFER_SIZE] = {0};

    fp = fopen(filename, "r");
    if (fp == NULL) {
        log_e("opening config file %s failed", filename);
        return;
    }

    while (fgets(line, sizeof(line), fp) != NULL) {
        if (line[0] == '#' || line[0] == '\n') {
            continue;
        }

        memset(key, 0, sizeof(key));
        memset(value, 0, sizeof(value));
        if (sscanf(line, "%[^=]=%s", key, value) == 2) {
        }
    }

    fclose(fp);
    return;
}

void load_default_config(daemon_opts_t* opts)
{
    opts->loglevel = LOG_ERR;

    return;
}

int main(int argc, char* const argv[])
{
    int c;
    const char* configfile = NULL;

    load_default_config(&opts);
    while ((c = getopt_long(argc, argv, "hvbl:", long_options, NULL)) != -1) {
        switch (c) {
            case 'v':
                printf("%s\n", DAEMON_VERSION);
                goto exit;
            case 'b':
                opts.background = 1;
                break;
            case 'l':
                opts.loglevel = atoi(optarg);
                break;
            case 1:
                configfile = optarg;
                break;
            case 'h':
            default:
                printf("Usage: daemon [options]\n");
                printf("  -h, --help          Show this help message\n");
                printf("  -v, --version       Show version\n");
                printf("  -b, --background    Run in background\n");
                printf("  -l, --log           Set log level, 1~7, default : 3\n");
                goto exit;
        }
    }

    if(opts.background) {
        daemonize();
    }

    openlog("daemon", LOG_PID, LOG_DAEMON);
    setlogmask(LOG_UPTO(opts.loglevel));
    log_i("daemon %s started...", DAEMON_VERSION);

    if(configfile) {
        load_config(configfile, &opts);
    }

    signal(SIGTERM, handle_signal);

    // do something

exit:
    log_i("daemon exit.");
    closelog();

    return 0;
}