CC=$(CROSS_COMPILE)gcc
CFLAGS=-I../

TARGET= inotify
all: $(TARGET)

$(TARGET):
	$(CC) $(CFLAGS) -o $(TARGET) inotify.c

.PHONY: all clean $(TARGET)
clean:
	rm -rf $(TARGET)

