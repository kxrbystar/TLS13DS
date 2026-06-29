#include <3ds.h>

#include <cstdio>
#include <cstring>
#include <string>

#include "tls13_3ds.h"

namespace {

void waitForExit() {
  std::puts("\nPress START to exit.");
  while (aptMainLoop()) {
    hidScanInput();
    if (hidKeysDown() & KEY_START) break;
    gspWaitForVBlank();
  }
}

}  // namespace

int main() {
  gfxInitDefault();
  consoleInit(GFX_TOP, nullptr);

  std::puts("tls13-3ds HTTPS GET example");

  alignas(0x1000) static u32 soc_buffer[0x100000 / sizeof(u32)];
  Result rc = socInit(soc_buffer, sizeof(soc_buffer));
  if (R_FAILED(rc)) {
    std::printf("socInit failed: 0x%08lx\n", static_cast<unsigned long>(rc));
    waitForExit();
    gfxExit();
    return 1;
  }

  rc = sslcInit(0);
  if (R_FAILED(rc)) {
    std::printf("sslcInit failed: 0x%08lx\n", static_cast<unsigned long>(rc));
    socExit();
    waitForExit();
    gfxExit();
    return 1;
  }

  tls13_3ds::TlsOptions options;
  options.verify_peer = false;
  options.alpn = {"http/1.1"};

  tls13_3ds::TlsSocket socket;
  if (!socket.connect("example.com", 443, options)) {
    std::printf("connect failed: %s\n", socket.lastError().c_str());
    sslcExit();
    socExit();
    waitForExit();
    gfxExit();
    return 1;
  }

  std::printf("TLS: %s\n", socket.negotiatedVersion().c_str());
  std::printf("Cipher: %s\n", socket.negotiatedCipherSuite().c_str());

  const char* request =
      "GET / HTTP/1.1\r\n"
      "Host: example.com\r\n"
      "Connection: close\r\n"
      "Accept: */*\r\n"
      "\r\n";

  if (!socket.writeAll(request)) {
    std::printf("write failed: %s\n", socket.lastError().c_str());
  } else {
    std::string line;
    if (socket.readLine(line)) {
      std::printf("Status: %s", line.c_str());
    }

    size_t bytes = 0;
    uint8_t buffer[1024];
    while (true) {
      int n = socket.read(buffer, sizeof(buffer), 2000);
      if (n <= 0) break;
      bytes += static_cast<size_t>(n);
    }
    std::printf("Body/header bytes after status: %lu\n",
                static_cast<unsigned long>(bytes));
  }

  socket.close();
  sslcExit();
  socExit();
  waitForExit();
  gfxExit();
  return 0;
}
