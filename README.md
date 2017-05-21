# ssl-proxy
A simple SSL/TLS proxy using libevent.

This is a fork of [le-proxy.c](https://github.com/libevent/libevent/blob/master/sample/le-proxy.c)
from [libevent](https://github.com/libevent/libevent).

# Build

libevent and OpenSSL are required. On Ubuntu, you can install them using the code below:

```
sudo apt-get install libevent-dev libssl-dev
```

Then just type `make` to build.

# Usage

## Install a forward HTTP proxy server

ssl-proxy works as an SSL/TLS tunnel between server and client. It doesn't handle HTTP protocol.
It can only be used with a forward HTTP proxy server. You can install `squid` or `apache`,
but not `nginx`, which doesn't support `CONNECT`.

## Create a self-signed certificate

ssl-proxy uses SSL certificate to secure its connections, which you can easily create using the OpenSSL package:

```
openssl req -x509 -newkey rsa:2048 -keyout key.pem -out cert.pem -days 365 -nodes
```

Note that when creating the certificate, you will be asked for some information such as country and state,
which you can enter whatever you like but when asked for "Common Name" you must enter the correct host name
or IP address of your server.

## Run ssl-proxy

Suppose the forward HTTP proxy server is listening on `127.0.0.1:8080`, then run ssl-proxy in server mode:

```
./ssl-proxy -server -cert cert.pem -key key.pem 0.0.0.0:8443 127.0.0.1:8080
```

And on your local machine, run ssl-proxy in client mode:

```
./ssl-proxy 127.0.0.1:8080 your-server-ip:8443
```

Now you have an HTTP proxy server listening on `127.0.0.1:8080` on your local machine, which will encrypt
incoming packets and forward them to the remote ssl-proxy, and the remote ssl-proxy will decrypt them and
forward the original packets to the forward HTTP proxy server.

### Use ssl-proxy as an HTTPS proxy server

If your application supports HTTPS proxy, you can skip running ssl-proxy on your local machine.

For example, you can start Chrome with the `--proxy-server=https://<proxy>:<port>` command line argument:

```
chrome --proxy-server=https://your-server-ip:8443
```

In this case, you may want to install the generated certificate as a Trusted Root CA to avoid your browser
complaining about it.
