# TLS13DS

Standalone TLS client library for Nintendo 3DS homebrew with TLS 1.2 and TLS 1.3 support.

This repository is extracted from a larger application. The TLS protocol
implementation is mbedTLS; this project provides the 3DS platform hooks,
socket glue, timeout handling, and a small C++ API that is practical to embed in
homebrew.

TLS13DS bundles mbedTLS 3.6.6 (Apache-2.0). Upstream: https://github.com/Mbed-TLS/mbedtls

## Features

- TLS 1.2 and TLS 1.3 client support
- SNI
- ALPN
- AES-GCM and ChaCha20-Poly1305 suites through mbedTLS
- 3DS hardware entropy via `sslcGenerateRandomData`
- 3DS millisecond clock via `osGetTime`
- blocking-style `read`, `writeAll`, `readLine`, and `readExact` helpers with
  timeouts

## Requirements

- devkitPro / devkitARM
- libctru
- mbedTLS 3.6.6 source tree in `mbedTLS/mbedtls-3.6.6`

The checked-in `mbedTLS/3ds_mbedtls_config.h` is the configuration used for
the 3DS build.

> [!CAUTION]
> TLS13DS is experimental software and should not yet be considered production-ready.
> The library is under active development and has only been tested on a launch-model Nintendo 3DS (CTR-001).

## Build

Build mbedTLS first:

```sh
make mbedtls
```

Build the wrapper library:

```sh
make
```

Build the example 3DSX:

```sh
make example
```

Install the public header and static library into devkitPro portlibs:

```sh
make install
```

## Basic Usage

```cpp
#include "tls13_3ds.h"

tls13_3ds::TlsOptions options;
options.verify_peer = false;      // Provide CA data and set true in real apps.
options.alpn = {"http/1.1"};

tls13_3ds::TlsSocket socket;
if (!socket.connect("example.com", 443, options)) {
  // socket.lastError()
}

socket.writeAll(
    "GET / HTTP/1.1\r\n"
    "Host: example.com\r\n"
    "Connection: close\r\n"
    "\r\n");
```

Your app must initialize 3DS networking services before using the socket:

```cpp
socInit(...);
sslcInit(0);
```

## Certificate Verification

The default options leave peer verification disabled so the example can run
without bundling a CA store. That is not suitable for production applications.

For real use, pass PEM root certificates in `TlsOptions::ca_pem` and set
`TlsOptions::verify_peer = true`.

## What This Is Not

This is not a new TLS implementation and does not use the 3DS SSL service as
the TLS engine. mbedTLS performs the TLS protocol work. The 3DS-specific parts
are the entropy source, time source, socket connection handling, and the
`mbedtls_ssl_set_bio` transport callbacks.

## License

The TLS13DS wrapper code located in include/, source/, and examples/ is licensed under the terms specified in LICENSE.
The bundled mbedTLS source code is licensed under the Apache License 2.0. See mbedTLS/mbedtls-3.6.6/LICENSE for details.
Projects using TLS13DS are requested to include the following attribution in their documentation, README, credits section, about page, or equivalent location:

Uses TLS13DS by Niklas Burtscher / kxrbystar

## Support Ukraine 🇺🇦

If you would like to help protect Ukrainian civilians from Russian missile and drone attacks, consider supporting the official UNITED24 Sky Defense fundraiser:
https://u24.gov.ua/sky-defense
