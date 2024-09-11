#include <stdio.h>
#include <unistd.h>
#include <sys/inotify.h>

typedef enum {
	DEV_CREATE,
	DEV_DELETE
} device_event_type_t;
typedef void (*event_callback_t)(const char* name, device_event_type_t type);

int do_device_monitoring(const char* path, event_callback_t callback)
{
	int length, i = 0;
	int fd;
	int wd;
	char buffer[1024 * (sizeof(struct inotify_event) + 16)];
	device_event_type_t etype;
	struct inotify_event* event = NULL;

	fd = inotify_init();
	if (fd < 0) {
		return -1;
	}

	wd = inotify_add_watch(fd, path, IN_CREATE | IN_DELETE);
	if (wd < 0) {
		close(fd);
		return -2;
	}

	while (1) {
		length = read(fd, buffer, sizeof(buffer));
		if (length < 0) {
			break;
		}

		while (i < length) {
			event = (struct inotify_event*)&buffer[i];
			if (event->len) {
				etype = (event->mask & IN_CREATE) ? DEV_CREATE : DEV_DELETE;
				if (callback) {
					callback(event->name, etype);
				}
			}
			i += sizeof(struct inotify_event) + event->len;
		}
		i = 0;
	}

	inotify_rm_watch(fd, wd);
	close(fd);
	return 0;
}

int main(int argc, char* const argv[])
{
	do_device_monitoring("/dev", NULL);

	return 0;
}