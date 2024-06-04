# Nginx
> [!NOTE]
> This charm is under maintenance mode. Only critical bug will be handled.

## Description

Nginx is an HTTP and reverse proxy server, a mail proxy server, and a generic TCP/UDP proxy server, originally written by Igor Sysoev. 

## Usage

The charm can be deployed using juju:
```
juju deploy ch:fe-staging-nginx
```

## Enable TLS

TLS is enabled when the ssl_cert (certificate) and ssl_key (private key) 
parameters are present, and ca_cert (CA certificate) is optional. The values
must be passed as base64 encoded strings.

```
$ juju config nginx \
  ssl_cert="$(base64 ./repo1.example.com.crt)" \
  ssl_key="$(base64 ./repo1.example.com.key)" \
  port=443
```

Validate TLS endpoint:

```
curl https://repo1.example.com -I
HTTP/1.1 200 OK
Server: nginx
Date: Thu, 07 Apr 2022 18:25:00 GMT
Content-Type: text/html
Content-Length: 612
Last-Modified: Tue, 21 Apr 2020 14:09:01 GMT
Connection: keep-alive
ETag: "5e9efe7d-264"
Accept-Ranges: bytes
```

## Developing

Create and activate a virtualenv,
and install the development requirements,

    virtualenv -p python3 venv
    source venv/bin/activate
    pip install -r requirements-dev.txt

## Testing

Just run `run_tests`:

    ./run_tests
