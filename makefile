TARGET = netfilter-test

CFLAGS = $(shell pkg-config --cflags libnetfilter_queue libmnl)
LIBS = $(shell pkg-config --libs libnetfilter_queue libmnl)

all: $(TARGET)

$(TARGET): netfilter-test.c
	$(CC) -o $(TARGET) netfilter-test.c $(CFLAGS) $(LIBS)

clean:
	rm -f $(TARGET)