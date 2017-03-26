CFLAGS = -g -O2 -Wall
LDLIBS = -levent_openssl -levent_core -lssl -lcrypto

.PHONY: clean

ssl-proxy: ssl-proxy.c
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS) $(LDLIBS)

clean:
	$(RM) ssl-proxy
