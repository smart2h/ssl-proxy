/*
  This example code shows how to write an (optionally encrypting) SSL proxy
  with Libevent's bufferevent layer.

  XXX It's a little ugly and should probably be cleaned up.
 */

// Get rid of OSX 10.7 and greater deprecation warnings.
#if defined(__APPLE__) && defined(__clang__)
#pragma clang diagnostic ignored "-Wdeprecated-declarations"
#endif

#include <stdio.h>
#include <assert.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>

#ifdef _WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
#else
#include <sys/socket.h>
#include <netinet/in.h>
#endif

#include <event2/bufferevent_ssl.h>
#include <event2/bufferevent.h>
#include <event2/buffer.h>
#include <event2/listener.h>
#include <event2/util.h>

#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/rand.h>

static struct event_base *base;
static struct sockaddr_storage listen_on_addr;
static struct sockaddr_storage connect_to_addr;
static int connect_to_addrlen;
static int server_mode = 0;
static const char *program_name = NULL;

static SSL_CTX *ssl_ctx = NULL;

#define MAX_OUTPUT (512*1024)

static void drained_writecb(struct bufferevent *bev, void *ctx);
static void eventcb(struct bufferevent *bev, short what, void *ctx);

static void
readcb(struct bufferevent *bev, void *ctx)
{
	struct bufferevent *partner = ctx;
	struct evbuffer *src, *dst;
	size_t len;
	src = bufferevent_get_input(bev);
	len = evbuffer_get_length(src);
	if (!partner) {
		evbuffer_drain(src, len);
		return;
	}
	dst = bufferevent_get_output(partner);
	evbuffer_add_buffer(dst, src);

	if (evbuffer_get_length(dst) >= MAX_OUTPUT) {
		/* We're giving the other side data faster than it can
		 * pass it on.  Stop reading here until we have drained the
		 * other side to MAX_OUTPUT/2 bytes. */
		bufferevent_setcb(partner, readcb, drained_writecb,
		    eventcb, bev);
		bufferevent_setwatermark(partner, EV_WRITE, MAX_OUTPUT/2,
		    MAX_OUTPUT);
		bufferevent_disable(bev, EV_READ);
	}
}

static void
drained_writecb(struct bufferevent *bev, void *ctx)
{
	struct bufferevent *partner = ctx;

	/* We were choking the other side until we drained our outbuf a bit.
	 * Now it seems drained. */
	bufferevent_setcb(bev, readcb, NULL, eventcb, partner);
	bufferevent_setwatermark(bev, EV_WRITE, 0, 0);
	if (partner)
		bufferevent_enable(partner, EV_READ);
}

static void
close_on_finished_writecb(struct bufferevent *bev, void *ctx)
{
	struct evbuffer *b = bufferevent_get_output(bev);

	if (evbuffer_get_length(b) == 0) {
		bufferevent_free(bev);
	}
}

static void
eventcb(struct bufferevent *bev, short what, void *ctx)
{
	struct bufferevent *partner = ctx;

	if (what & (BEV_EVENT_EOF|BEV_EVENT_ERROR)) {
		if (what & BEV_EVENT_ERROR) {
			unsigned long err;
			while ((err = (bufferevent_get_openssl_error(bev)))) {
				const char *msg = (const char*)
				    ERR_reason_error_string(err);
				const char *lib = (const char*)
				    ERR_lib_error_string(err);
				const char *func = (const char*)
				    ERR_func_error_string(err);
				fprintf(stderr,
				    "%s in %s %s\n", msg, lib, func);
			}
			if (errno)
				perror("connection error");
		}

		if (partner) {
			/* Flush all pending data */
			readcb(bev, ctx);

			if (evbuffer_get_length(
				    bufferevent_get_output(partner))) {
				/* We still have to flush data from the other
				 * side, but when that's done, close the other
				 * side. */
				bufferevent_setcb(partner,
				    NULL, close_on_finished_writecb,
				    eventcb, NULL);
				bufferevent_disable(partner, EV_READ);
			} else {
				/* We have nothing left to say to the other
				 * side; close it. */
				bufferevent_free(partner);
			}
		}
		bufferevent_free(bev);
	}
}

static void
syntax(void)
{
	fputs("Syntax:\n", stderr);
	fprintf(stderr, "   %s [-server -cert certificate_chain_file -key private_key_file] <listen-on-addr> <connect-to-addr>\n", program_name);
	fputs("Example:\n", stderr);
	fprintf(stderr, "   %s -server -cert certificate_chain_file -key private_key_file 0.0.0.0:8443 127.0.0.1:8080\n", program_name);
	fprintf(stderr, "   %s 127.0.0.1:8080 1.2.3.4:8443\n", program_name);

	exit(1);
}

static void
accept_cb(struct evconnlistener *listener, evutil_socket_t fd,
    struct sockaddr *a, int slen, void *p)
{
	struct bufferevent *b_out, *b_in;
	SSL *ssl = SSL_new(ssl_ctx);

	/* Create two linked bufferevent objects: one to connect, one for the
	 * new connection */
	if (server_mode) {
		b_in = bufferevent_openssl_socket_new(base, fd, ssl, BUFFEREVENT_SSL_ACCEPTING,
		    BEV_OPT_CLOSE_ON_FREE|BEV_OPT_DEFER_CALLBACKS);
		b_out = bufferevent_socket_new(base, -1,
		    BEV_OPT_CLOSE_ON_FREE|BEV_OPT_DEFER_CALLBACKS);
	} else {
		b_in = bufferevent_socket_new(base, fd,
		    BEV_OPT_CLOSE_ON_FREE|BEV_OPT_DEFER_CALLBACKS);
		b_out = bufferevent_openssl_socket_new(base, -1, ssl,
		    BUFFEREVENT_SSL_CONNECTING,
		    BEV_OPT_CLOSE_ON_FREE|BEV_OPT_DEFER_CALLBACKS);
	}

	assert(b_in && b_out);

	if (bufferevent_socket_connect(b_out,
		(struct sockaddr*)&connect_to_addr, connect_to_addrlen)<0) {
		perror("bufferevent_socket_connect");
		bufferevent_free(b_out);
		bufferevent_free(b_in);
		return;
	}

	bufferevent_setcb(b_in, readcb, NULL, eventcb, b_out);
	bufferevent_setcb(b_out, readcb, NULL, eventcb, b_in);

	bufferevent_enable(b_in, EV_READ|EV_WRITE);
	bufferevent_enable(b_out, EV_READ|EV_WRITE);
}

static int
init_ssl(const char *certificate_chain_file, const char *private_key_file)
{
	int r;
#if (OPENSSL_VERSION_NUMBER < 0x10100000L) || defined(LIBRESSL_VERSION_NUMBER)
#define TLS_method SSLv23_method
	SSL_library_init();
	ERR_load_crypto_strings();
	SSL_load_error_strings();
	OpenSSL_add_all_algorithms();
#endif
	r = RAND_poll();
	if (r == 0) {
		fprintf(stderr, "RAND_poll() failed.\n");
		return 1;
	}
	ssl_ctx = SSL_CTX_new(TLS_method());
	SSL_CTX_set_options(ssl_ctx, SSL_OP_NO_SSLv3);
	if (server_mode) {
		if (!SSL_CTX_use_certificate_chain_file(ssl_ctx, certificate_chain_file) ||
			!SSL_CTX_use_PrivateKey_file(ssl_ctx, private_key_file, SSL_FILETYPE_PEM)) {
			fprintf(stderr, "Couldn't read %s or %s.\n", certificate_chain_file, private_key_file);
			return 2;
		}
	}
	return 0;
}

int
main(int argc, char **argv)
{
	int i;
	int socklen;
	const char *certificate_chain_file = NULL;
	const char *private_key_file = NULL;

	struct evconnlistener *listener;

	program_name = argv[0];

	if (argc < 3)
		syntax();

	for (i=1; i < argc; ++i) {
		if (!strcmp(argv[i], "-server")) {
			server_mode = 1;
		} else if (!strcmp(argv[i], "-cert")) {
			if (i + 1 >= argc) {
				syntax();
			}
			certificate_chain_file = argv[++i];
		} else if (!strcmp(argv[i], "-key")) {
			if (i + 1 >= argc) {
				syntax();
			}
			private_key_file = argv[++i];
		} else if (argv[i][0] == '-') {
			syntax();
		} else
			break;
	}

	if (server_mode) {
		if (!certificate_chain_file || !private_key_file) {
			fputs("Should specify certificate_chain_file and private_key_file when in server mode.\n", stderr);
			return 1;
		}
	}

	if (i+2 != argc)
		syntax();

	memset(&listen_on_addr, 0, sizeof(listen_on_addr));
	socklen = sizeof(listen_on_addr);
	if (evutil_parse_sockaddr_port(argv[i],
		(struct sockaddr*)&listen_on_addr, &socklen)<0) {
		int p = atoi(argv[i]);
		struct sockaddr_in *sin = (struct sockaddr_in*)&listen_on_addr;
		if (p < 1 || p > 65535)
			syntax();
		sin->sin_port = htons(p);
		sin->sin_addr.s_addr = htonl(0x7f000001);
		sin->sin_family = AF_INET;
		socklen = sizeof(struct sockaddr_in);
	}

	memset(&connect_to_addr, 0, sizeof(connect_to_addr));
	connect_to_addrlen = sizeof(connect_to_addr);
	if (evutil_parse_sockaddr_port(argv[i+1],
		(struct sockaddr*)&connect_to_addr, &connect_to_addrlen)<0)
		syntax();

	base = event_base_new();
	if (!base) {
		perror("event_base_new()");
		return 1;
	}

    if (init_ssl(certificate_chain_file, private_key_file) != 0) {
		return 1;
	}

	listener = evconnlistener_new_bind(base, accept_cb, NULL,
	    LEV_OPT_CLOSE_ON_FREE|LEV_OPT_CLOSE_ON_EXEC|LEV_OPT_REUSEABLE,
	    -1, (struct sockaddr*)&listen_on_addr, socklen);

	if (! listener) {
		fprintf(stderr, "Couldn't open listener.\n");
		event_base_free(base);
		return 1;
	}
	event_base_dispatch(base);

	evconnlistener_free(listener);
	event_base_free(base);

	return 0;
}
