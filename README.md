# ssl-proxy

A simple SSL/TLS proxy built with libevent.

This project is based on [le-proxy.c](https://github.com/libevent/libevent/blob/master/sample/le-proxy.c) from [libevent](https://github.com/libevent/libevent).

## Build

Both libevent and OpenSSL are required. On Ubuntu, you can install them with:

```shell
sudo apt-get install libevent-dev libssl-dev
```

Then run `make`.

## Usage

### Example: Use with a forward HTTP proxy server

`ssl-proxy` acts as an SSL/TLS tunnel between a client and a server.

One example is to use it to secure traffic to a regular forward HTTP proxy server. You can use `Squid` or `Apache`, but not `Nginx`, because `Nginx` does not support `CONNECT`.

#### Generate a self-signed certificate

`ssl-proxy` requires an SSL/TLS certificate to secure its connections. You can easily generate a self-signed certificate using OpenSSL:

```shell
openssl req -x509 -newkey rsa:2048 -keyout key.pem -out cert.pem -days 365 -nodes
```

Note: When generating the certificate, you will be prompted to enter information such as your country and state. You can enter any values you prefer for these fields. However, when asked for the "Common Name", you must enter the exact hostname or IP address of your remote server.

#### Run ssl-proxy

Assuming your forward HTTP proxy server is already running and listening on `127.0.0.1:8080`, start `ssl-proxy` in server mode on your remote machine:

```shell
./ssl-proxy -server -cert cert.pem -key key.pem 0.0.0.0:8443 127.0.0.1:8080
```

Next, on your local machine, run `ssl-proxy` in client mode:

```shell
./ssl-proxy 127.0.0.1:8080 <your-server-ip>:8443
```

This sets up an HTTP proxy listening on `127.0.0.1:8080` on your local machine. It encrypts incoming traffic, forwards it to the remote `ssl-proxy`, and the remote `ssl-proxy` decrypts it before forwarding the original traffic to the forward HTTP proxy server.

#### Use ssl-proxy as an HTTPS proxy server

If your client application supports HTTPS proxies, you can skip running `ssl-proxy` on your local machine.

For example, you can launch Chrome with the `--proxy-server=https://<proxy>:<port>` command-line flag:

```shell
chrome --proxy-server=https://<your-server-ip>:8443
```

In this case, you may need to install the generated certificate as a trusted root CA to avoid browser warnings.
