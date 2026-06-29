#pragma once

#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

namespace tls13_3ds {

struct TlsOptions {
  uint32_t tcp_timeout_ms = 8000;
  uint32_t tls_timeout_ms = 12000;
  uint32_t io_timeout_ms = 8000;
  uint32_t bio_poll_ms = 50;

  // Disabled by default so the tiny example works without shipping a CA bundle.
  // Public applications should provide ca_pem and enable verification.
  bool verify_peer = false;
  std::string ca_pem;

  std::vector<std::string> alpn;
};

class TlsSocket {
 public:
  TlsSocket();
  ~TlsSocket();

  TlsSocket(const TlsSocket&) = delete;
  TlsSocket& operator=(const TlsSocket&) = delete;

  bool connect(const std::string& host, int port,
               const TlsOptions& options = TlsOptions{});
  void close();

  int read(uint8_t* data, size_t length, uint32_t timeout_ms = 0);
  bool readExact(uint8_t* data, size_t length, uint32_t timeout_ms = 0);
  bool readLine(std::string& out, size_t max_len = 8192,
                uint32_t timeout_ms = 0);

  int write(const uint8_t* data, size_t length, uint32_t timeout_ms = 0);
  bool writeAll(const uint8_t* data, size_t length, uint32_t timeout_ms = 0);
  bool writeAll(const std::string& text, uint32_t timeout_ms = 0);

  bool isOpen() const { return opened_; }
  const std::string& lastError() const { return last_error_; }
  std::string negotiatedVersion() const;
  std::string negotiatedCipherSuite() const;
  std::string negotiatedAlpn() const;

 private:
  struct Impl;
  Impl* impl_;
  bool opened_ = false;
  std::string last_error_;
};

const char* version();

}  // namespace tls13_3ds
