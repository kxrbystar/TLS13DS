#include "tls13_3ds.h"

#include <3ds.h>

#include <mbedtls/ctr_drbg.h>
#include <mbedtls/entropy.h>
#include <mbedtls/error.h>
#include <mbedtls/net_sockets.h>
#include <mbedtls/ssl.h>
#include <mbedtls/x509_crt.h>
#include <psa/crypto.h>

#include <algorithm>
#include <cerrno>
#include <cstdio>
#include <cstring>
#include <fcntl.h>
#include <netdb.h>
#include <string>
#include <sys/select.h>
#include <sys/socket.h>
#include <unistd.h>

namespace tls13_3ds {
namespace {

uint64_t nowMs() {
  return static_cast<uint64_t>(osGetTime());
}

uint64_t deadlineMs(uint32_t timeout_ms) {
  return nowMs() + timeout_ms;
}

uint32_t remainingMs(uint64_t deadline) {
  const uint64_t now = nowMs();
  if (now >= deadline) return 0;
  const uint64_t remaining = deadline - now;
  return remaining > UINT32_MAX ? UINT32_MAX : static_cast<uint32_t>(remaining);
}

std::string mbedError(int ret) {
  char buffer[160] = {};
  mbedtls_strerror(ret, buffer, sizeof(buffer));
  return buffer[0] ? std::string(buffer) : std::string("unknown mbedTLS error");
}

bool setNonBlocking(int fd) {
  int flags = fcntl(fd, F_GETFL, 0);
  if (flags < 0) return false;
  return fcntl(fd, F_SETFL, flags | O_NONBLOCK) == 0;
}

bool setBlocking(int fd) {
  int flags = fcntl(fd, F_GETFL, 0);
  if (flags < 0) return false;
  return fcntl(fd, F_SETFL, flags & ~O_NONBLOCK) == 0;
}

bool waitForSocket(int fd, bool writable, uint64_t deadline) {
  while (true) {
    const uint32_t remaining = remainingMs(deadline);
    if (remaining == 0) return false;

    fd_set fds;
    FD_ZERO(&fds);
    FD_SET(fd, &fds);

    timeval tv;
    tv.tv_sec = remaining / 1000;
    tv.tv_usec = (remaining % 1000) * 1000;

    const int rc = select(fd + 1, writable ? nullptr : &fds,
                          writable ? &fds : nullptr, nullptr, &tv);
    if (rc > 0 && FD_ISSET(fd, &fds)) return true;
    if (rc == 0) return false;
    if (errno == EINTR) continue;
    return false;
  }
}

int connectOneAddress(const sockaddr* address, socklen_t address_len,
                      uint64_t deadline) {
  int fd = socket(address->sa_family, SOCK_STREAM, 0);
  if (fd < 0) return -1;

  if (!setNonBlocking(fd)) {
    close(fd);
    return -1;
  }

  int rc = ::connect(fd, address, address_len);
  if (rc == 0) {
    setBlocking(fd);
    return fd;
  }

  if (errno != EINPROGRESS && errno != EWOULDBLOCK && errno != EAGAIN) {
    close(fd);
    return -1;
  }

  if (!waitForSocket(fd, true, deadline)) {
    close(fd);
    return -1;
  }

  int so_error = 0;
  socklen_t so_len = sizeof(so_error);
  if (getsockopt(fd, SOL_SOCKET, SO_ERROR, &so_error, &so_len) != 0 ||
      so_error != 0) {
    close(fd);
    return -1;
  }

  setBlocking(fd);
  return fd;
}

int connectTcp(const std::string& host, int port, uint32_t timeout_ms,
               std::string& error) {
  addrinfo hints = {};
  hints.ai_family = AF_INET;
  hints.ai_socktype = SOCK_STREAM;
  hints.ai_protocol = IPPROTO_IP;

  char port_text[8];
  std::snprintf(port_text, sizeof(port_text), "%d", port);

  addrinfo* results = nullptr;
  const int gai = getaddrinfo(host.c_str(), port_text, &hints, &results);
  if (gai != 0 || !results) {
    error = "DNS lookup failed";
    return -1;
  }

  const uint64_t deadline = deadlineMs(timeout_ms);
  int fd = -1;
  for (addrinfo* ai = results; ai && nowMs() < deadline; ai = ai->ai_next) {
    fd = connectOneAddress(ai->ai_addr, ai->ai_addrlen, deadline);
    if (fd >= 0) break;
  }
  freeaddrinfo(results);

  if (fd < 0) error = "TCP connect failed or timed out";
  return fd;
}

}  // namespace

struct TlsSocket::Impl {
  int fd = -1;
  TlsOptions options;
  mbedtls_net_context net;
  mbedtls_entropy_context entropy;
  mbedtls_ctr_drbg_context ctr_drbg;
  mbedtls_ssl_context ssl;
  mbedtls_ssl_config conf;
  mbedtls_x509_crt ca;

  Impl() { reset(); }

  ~Impl() { free(); }

  void reset() {
    mbedtls_net_init(&net);
    mbedtls_entropy_init(&entropy);
    mbedtls_ctr_drbg_init(&ctr_drbg);
    mbedtls_ssl_init(&ssl);
    mbedtls_ssl_config_init(&conf);
    mbedtls_x509_crt_init(&ca);
  }

  void free() {
    mbedtls_ssl_free(&ssl);
    mbedtls_ssl_config_free(&conf);
    mbedtls_ctr_drbg_free(&ctr_drbg);
    mbedtls_entropy_free(&entropy);
    mbedtls_x509_crt_free(&ca);
    reset();
  }

  static int sendCallback(void* ctx, const unsigned char* buf, size_t len) {
    auto* self = static_cast<Impl*>(ctx);
    if (!self) return MBEDTLS_ERR_SSL_BAD_INPUT_DATA;
    return mbedtls_net_send(&self->net, buf, len);
  }

  static int recvTimeoutCallback(void* ctx, unsigned char* buf, size_t len,
                                 uint32_t timeout) {
    auto* self = static_cast<Impl*>(ctx);
    if (!self) return MBEDTLS_ERR_SSL_BAD_INPUT_DATA;
    return mbedtls_net_recv_timeout(&self->net, buf, len, timeout);
  }
};

TlsSocket::TlsSocket() : impl_(new Impl()) {}

TlsSocket::~TlsSocket() {
  close();
  delete impl_;
}

bool TlsSocket::connect(const std::string& host, int port,
                        const TlsOptions& options) {
  close();
  impl_->free();
  impl_->options = options;
  last_error_.clear();

  impl_->fd = connectTcp(host, port, options.tcp_timeout_ms, last_error_);
  if (impl_->fd < 0) return false;
  impl_->net.fd = impl_->fd;
  opened_ = true;

  psa_status_t psa_rc = psa_crypto_init();
  if (psa_rc != PSA_SUCCESS) {
    last_error_ = "psa_crypto_init failed";
    close();
    return false;
  }

  const char* pers = "tls13_3ds";
  int ret = mbedtls_ctr_drbg_seed(
      &impl_->ctr_drbg, mbedtls_entropy_func, &impl_->entropy,
      reinterpret_cast<const unsigned char*>(pers), std::strlen(pers));
  if (ret != 0) {
    last_error_ = "RNG seed failed: " + mbedError(ret);
    close();
    return false;
  }

  ret = mbedtls_ssl_config_defaults(&impl_->conf, MBEDTLS_SSL_IS_CLIENT,
                                    MBEDTLS_SSL_TRANSPORT_STREAM,
                                    MBEDTLS_SSL_PRESET_DEFAULT);
  if (ret != 0) {
    last_error_ = "TLS config defaults failed: " + mbedError(ret);
    close();
    return false;
  }

  mbedtls_ssl_conf_min_tls_version(&impl_->conf, MBEDTLS_SSL_VERSION_TLS1_2);
  mbedtls_ssl_conf_max_tls_version(&impl_->conf, MBEDTLS_SSL_VERSION_TLS1_3);
  mbedtls_ssl_conf_rng(&impl_->conf, mbedtls_ctr_drbg_random, &impl_->ctr_drbg);
  mbedtls_ssl_conf_read_timeout(&impl_->conf, options.bio_poll_ms);

  if (!options.ca_pem.empty()) {
    ret = mbedtls_x509_crt_parse(
        &impl_->ca, reinterpret_cast<const unsigned char*>(options.ca_pem.c_str()),
        options.ca_pem.size() + 1);
    if (ret != 0) {
      last_error_ = "CA parse failed: " + mbedError(ret);
      close();
      return false;
    }
    mbedtls_ssl_conf_ca_chain(&impl_->conf, &impl_->ca, nullptr);
  }

  mbedtls_ssl_conf_authmode(&impl_->conf,
                            options.verify_peer ? MBEDTLS_SSL_VERIFY_REQUIRED
                                                : MBEDTLS_SSL_VERIFY_NONE);

#if defined(MBEDTLS_SSL_ALPN)
  std::vector<const char*> alpn_ptrs;
  for (const std::string& proto : options.alpn) {
    alpn_ptrs.push_back(proto.c_str());
  }
  alpn_ptrs.push_back(nullptr);
  if (!options.alpn.empty()) {
    ret = mbedtls_ssl_conf_alpn_protocols(&impl_->conf, alpn_ptrs.data());
    if (ret != 0) {
      last_error_ = "ALPN setup failed: " + mbedError(ret);
      close();
      return false;
    }
  }
#endif

  ret = mbedtls_ssl_setup(&impl_->ssl, &impl_->conf);
  if (ret != 0) {
    last_error_ = "TLS setup failed: " + mbedError(ret);
    close();
    return false;
  }

  ret = mbedtls_ssl_set_hostname(&impl_->ssl, host.c_str());
  if (ret != 0) {
    last_error_ = "SNI hostname setup failed: " + mbedError(ret);
    close();
    return false;
  }

  mbedtls_ssl_set_bio(&impl_->ssl, impl_, Impl::sendCallback, nullptr,
                      Impl::recvTimeoutCallback);

  const uint64_t deadline = deadlineMs(options.tls_timeout_ms);
  while ((ret = mbedtls_ssl_handshake(&impl_->ssl)) != 0) {
    if (ret == MBEDTLS_ERR_SSL_WANT_READ || ret == MBEDTLS_ERR_SSL_TIMEOUT) {
      if (!waitForSocket(impl_->fd, false, deadline)) {
        last_error_ = "TLS handshake timed out waiting for read";
        close();
        return false;
      }
      continue;
    }
    if (ret == MBEDTLS_ERR_SSL_WANT_WRITE) {
      if (!waitForSocket(impl_->fd, true, deadline)) {
        last_error_ = "TLS handshake timed out waiting for write";
        close();
        return false;
      }
      continue;
    }

    last_error_ = "TLS handshake failed: " + mbedError(ret);
    close();
    return false;
  }

  return true;
}

void TlsSocket::close() {
  if (opened_) {
    (void)mbedtls_ssl_close_notify(&impl_->ssl);
  }
  if (impl_->fd >= 0) {
    ::close(impl_->fd);
    impl_->fd = -1;
  }
  impl_->free();
  opened_ = false;
}

int TlsSocket::read(uint8_t* data, size_t length, uint32_t timeout_ms) {
  if (!opened_ || !data || length == 0) return 0;
  const uint64_t deadline =
      deadlineMs(timeout_ms ? timeout_ms : impl_->options.io_timeout_ms);

  while (nowMs() < deadline) {
    int ret = mbedtls_ssl_read(&impl_->ssl, data, length);
    if (ret > 0) return ret;
    if (ret == 0) return 0;
    if (ret == MBEDTLS_ERR_SSL_TIMEOUT) continue;
    if (ret == MBEDTLS_ERR_SSL_WANT_READ) {
      if (!waitForSocket(impl_->fd, false, deadline)) return -1;
      continue;
    }
    if (ret == MBEDTLS_ERR_SSL_WANT_WRITE) {
      if (!waitForSocket(impl_->fd, true, deadline)) return -1;
      continue;
    }
    last_error_ = "TLS read failed: " + mbedError(ret);
    return -1;
  }
  last_error_ = "TLS read timed out";
  return -1;
}

bool TlsSocket::readExact(uint8_t* data, size_t length, uint32_t timeout_ms) {
  size_t total = 0;
  const uint64_t deadline =
      deadlineMs(timeout_ms ? timeout_ms : impl_->options.io_timeout_ms);
  while (total < length) {
    const uint32_t remaining = remainingMs(deadline);
    if (remaining == 0) return false;
    int ret = read(data + total, length - total, remaining);
    if (ret <= 0) return false;
    total += static_cast<size_t>(ret);
  }
  return true;
}

bool TlsSocket::readLine(std::string& out, size_t max_len,
                         uint32_t timeout_ms) {
  out.clear();
  const uint64_t deadline =
      deadlineMs(timeout_ms ? timeout_ms : impl_->options.io_timeout_ms);
  while (out.size() < max_len) {
    uint8_t byte = 0;
    const uint32_t remaining = remainingMs(deadline);
    if (remaining == 0) return false;
    int ret = read(&byte, 1, remaining);
    if (ret <= 0) return false;
    out.push_back(static_cast<char>(byte));
    if (byte == '\n') return true;
  }
  last_error_ = "TLS line exceeded maximum length";
  return false;
}

int TlsSocket::write(const uint8_t* data, size_t length, uint32_t timeout_ms) {
  if (!opened_ || (!data && length > 0)) return -1;
  const uint64_t deadline =
      deadlineMs(timeout_ms ? timeout_ms : impl_->options.io_timeout_ms);

  while (nowMs() < deadline) {
    int ret = mbedtls_ssl_write(&impl_->ssl, data, length);
    if (ret > 0) return ret;
    if (ret == MBEDTLS_ERR_SSL_WANT_READ) {
      if (!waitForSocket(impl_->fd, false, deadline)) return -1;
      continue;
    }
    if (ret == MBEDTLS_ERR_SSL_WANT_WRITE) {
      if (!waitForSocket(impl_->fd, true, deadline)) return -1;
      continue;
    }
    last_error_ = "TLS write failed: " + mbedError(ret);
    return -1;
  }
  last_error_ = "TLS write timed out";
  return -1;
}

bool TlsSocket::writeAll(const uint8_t* data, size_t length,
                         uint32_t timeout_ms) {
  size_t total = 0;
  const uint64_t deadline =
      deadlineMs(timeout_ms ? timeout_ms : impl_->options.io_timeout_ms);
  while (total < length) {
    const uint32_t remaining = remainingMs(deadline);
    if (remaining == 0) return false;
    int ret = write(data + total, length - total, remaining);
    if (ret <= 0) return false;
    total += static_cast<size_t>(ret);
  }
  return true;
}

bool TlsSocket::writeAll(const std::string& text, uint32_t timeout_ms) {
  return writeAll(reinterpret_cast<const uint8_t*>(text.data()), text.size(),
                  timeout_ms);
}

std::string TlsSocket::negotiatedVersion() const {
  const char* value = mbedtls_ssl_get_version(&impl_->ssl);
  return value ? std::string(value) : std::string();
}

std::string TlsSocket::negotiatedCipherSuite() const {
  const char* value = mbedtls_ssl_get_ciphersuite(&impl_->ssl);
  return value ? std::string(value) : std::string();
}

std::string TlsSocket::negotiatedAlpn() const {
#if defined(MBEDTLS_SSL_ALPN)
  const char* value = mbedtls_ssl_get_alpn_protocol(&impl_->ssl);
  return value ? std::string(value) : std::string();
#else
  return {};
#endif
}

const char* version() {
  return "tls13-3ds 0.1.0";
}

}  // namespace tls13_3ds
