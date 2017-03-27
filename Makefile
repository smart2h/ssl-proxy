CFLAGS = -g -O2 -Wall
LDFLAGS = -levent_openssl -levent_core -lssl -lcrypto

ssl-proxy: ssl-proxy.c
	$(CC) -o $@ $^ $(CFLAGS) $(LDFLAGS)

clean:
	-rm -f ssl-proxy
