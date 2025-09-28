# http-logging-proxy

A simple HTTP proxy written in Go.

## Usage

```bash
go build -o goproxy .
./goproxy -logpath out.log
```

### Example

```bash
curl -k -x localhost:8080 https://example.com
cat out.log
```

Example log output:

```plain
=== 2025-09-28 14:30:25 REQUEST/RESPONSE PAIR ===
REQUEST:
GET / HTTP/1.1
Host: example.com
User-Agent: curl/8.0.1
Accept: */*


RESPONSE:
HTTP/1.1 200 OK
Content-Type: text/html; charset=UTF-8
Content-Length: 1256
Date: Sat, 28 Sep 2025 14:30:25 GMT

<!doctype html>
<html>
<head>
    <title>Example Domain</title>
...
[content truncated]
==================================================
```

### Options

```bash
./goproxy -port 8080                           # Custom port
./goproxy -logpath requests.log                # Log requests/responses
./goproxy -ca-cert ca.crt -ca-key ca.key       # Use custom CA
```

| Flag        | Default | Description                  |
|-------------|---------|------------------------------|
| `-port`     | 8080    | Port to listen on            |
| `-logpath`  |         | File to log HTTP traffic     |
| `-ca-cert`  |         | CA certificate file (PEM)    |
| `-ca-key`   |         | CA private key file (PEM)    |

## Features

- HTTP and HTTPS proxying with TLS termination
- CONNECT method support
- Optional request/response logging
- TCP passthrough for non-standard ports

## TLS Termination

For HTTPS traffic, this proxy terminates TLS connections and re-encrypts to upstream servers. Clients must be configured to trust the proxy's CA certificate for HTTPS requests.

CONNECT requests to ports 80 and 443 are handled with HTTP/HTTPS proxying. All other ports use TCP passthrough.
