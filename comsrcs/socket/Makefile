CC=$(CROSS_COMPILE)gcc
CFLAGS=-I../

TARGET= socket
all: $(TARGET)

$(TARGET):
	$(CC) $(CFLAGS) -o $(TARGET) socket.c ../util.c

.PHONY: all clean $(TARGET)
clean:
	rm -rf $(TARGET)

