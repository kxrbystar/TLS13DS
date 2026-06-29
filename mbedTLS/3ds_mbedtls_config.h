/* mbedTLS 3.6.x configuration for Nintendo 3DS
 *
 * Goals:
 *   - TLS 1.2 + TLS 1.3 client (no server, no DTLS)
 *   - ECDHE key exchange with X25519 / P-256 / P-384
 *   - AES-128/256-GCM and ChaCha20-Poly1305 cipher suites
 *   - RSA + ECDSA certificate support
 *   - PSA Crypto backend (required for TLS 1.3), in-memory keys only
 *   - Hardware entropy via sslcGenerateRandomData (provided in 3ds_hw_poll.c)
 */

/* ------------------------------------------------------------------ */
/* Platform                                                             */
/* ------------------------------------------------------------------ */
#define MBEDTLS_PLATFORM_C
#define MBEDTLS_HAVE_TIME
#define MBEDTLS_HAVE_TIME_DATE

/* 3DS has no /dev/urandom; we supply mbedtls_hardware_poll() */
#define MBEDTLS_NO_PLATFORM_ENTROPY
#define MBEDTLS_ENTROPY_HARDWARE_ALT

/* ------------------------------------------------------------------ */
/* Error / version                                                      */
/* ------------------------------------------------------------------ */
#define MBEDTLS_ERROR_C
#define MBEDTLS_VERSION_C

/* ------------------------------------------------------------------ */
/* Entropy + RNG                                                        */
/* ------------------------------------------------------------------ */
#define MBEDTLS_ENTROPY_C
#define MBEDTLS_CTR_DRBG_C
#define MBEDTLS_HMAC_DRBG_C   /* some PSA internals prefer this */

/* ------------------------------------------------------------------ */
/* Network layer (TCP client)                                           */
/* ------------------------------------------------------------------ */
#define MBEDTLS_NET_C

/* ------------------------------------------------------------------ */
/* ASN.1 / OID / PEM                                                   */
/* ------------------------------------------------------------------ */
#define MBEDTLS_ASN1_PARSE_C
#define MBEDTLS_ASN1_WRITE_C
#define MBEDTLS_OID_C
#define MBEDTLS_BASE64_C
#define MBEDTLS_PEM_PARSE_C

/* ------------------------------------------------------------------ */
/* Big integer                                                          */
/* ------------------------------------------------------------------ */
#define MBEDTLS_BIGNUM_C

/* ------------------------------------------------------------------ */
/* Hashing                                                              */
/* ------------------------------------------------------------------ */
#define MBEDTLS_MD_C
#define MBEDTLS_SHA1_C        /* legacy cert signatures */
#define MBEDTLS_MD5_C         /* legacy cert signatures */
#define MBEDTLS_SHA256_C      /* TLS 1.2 + TLS 1.3 PRF */
#define MBEDTLS_SHA384_C      /* TLS 1.3 AES-256-GCM and P-384 sig_algs */
#define MBEDTLS_SHA512_C      /* TLS 1.2 + TLS 1.3 P-521 suites */
#define MBEDTLS_HKDF_C        /* TLS 1.3 key schedule */

/* ------------------------------------------------------------------ */
/* Symmetric ciphers                                                    */
/* ------------------------------------------------------------------ */
#define MBEDTLS_CIPHER_C
#define MBEDTLS_CIPHER_MODE_CTR
#define MBEDTLS_AES_C
#define MBEDTLS_GCM_C             /* AES-128-GCM, AES-256-GCM */
#define MBEDTLS_CCM_C
#define MBEDTLS_CHACHA20_C
#define MBEDTLS_POLY1305_C
#define MBEDTLS_CHACHAPOLY_C      /* ChaCha20-Poly1305 */
#define MBEDTLS_PKCS5_C

/* ------------------------------------------------------------------ */
/* ECC                                                                  */
/* ------------------------------------------------------------------ */
#define MBEDTLS_ECP_C
#define MBEDTLS_ECDH_C
#define MBEDTLS_ECDSA_C
#define MBEDTLS_ECP_DP_CURVE25519_ENABLED   /* X25519 (TLS 1.3 key exchange) */
#define MBEDTLS_ECP_DP_SECP256R1_ENABLED    /* P-256 */
#define MBEDTLS_ECP_DP_SECP384R1_ENABLED    /* P-384 */
#define MBEDTLS_ECP_DP_SECP521R1_ENABLED    /* P-521 — needed for ECDSA_SECP521R1_SHA256 sig_alg to match librespot/rustls */
#define MBEDTLS_ECP_DP_CURVE448_ENABLED     /* X448 — advertised by common PC TLS stacks */
#define MBEDTLS_ECP_NIST_OPTIM

/* ------------------------------------------------------------------ */
/* RSA                                                                  */
/* ------------------------------------------------------------------ */
#define MBEDTLS_RSA_C
#define MBEDTLS_PKCS1_V15
#define MBEDTLS_PKCS1_V21

/* ------------------------------------------------------------------ */
/* Public key abstraction                                               */
/* ------------------------------------------------------------------ */
#define MBEDTLS_PK_C
#define MBEDTLS_PK_PARSE_C
#define MBEDTLS_PK_WRITE_C

/* ------------------------------------------------------------------ */
/* X.509 certificate parsing                                            */
/* ------------------------------------------------------------------ */
#define MBEDTLS_X509_USE_C
#define MBEDTLS_X509_CRT_PARSE_C
#define MBEDTLS_X509_CHECK_KEY_USAGE
#define MBEDTLS_X509_CHECK_EXTENDED_KEY_USAGE
#define MBEDTLS_X509_RSASSA_PSS_SUPPORT

/* ------------------------------------------------------------------ */
/* PSA Crypto (required by TLS 1.3)                                    */
/* In-memory keys only — no persistent storage needed.                 */
/* ------------------------------------------------------------------ */
#define MBEDTLS_PSA_CRYPTO_C
/* MBEDTLS_PSA_CRYPTO_STORAGE_C intentionally omitted (needs file ITS) */
/* MBEDTLS_PSA_ITS_FILE_C intentionally omitted (not available on 3DS) */

/* ------------------------------------------------------------------ */
/* TLS 1.2 key exchange modes                                          */
/* ------------------------------------------------------------------ */
#define MBEDTLS_KEY_EXCHANGE_ECDHE_RSA_ENABLED
#define MBEDTLS_KEY_EXCHANGE_ECDHE_ECDSA_ENABLED
#define MBEDTLS_KEY_EXCHANGE_RSA_ENABLED

/* ------------------------------------------------------------------ */
/* TLS (client only, no DTLS)                                          */
/* ------------------------------------------------------------------ */
#define MBEDTLS_SSL_TLS_C  /* internal name in mbedTLS 3.x (replaces MBEDTLS_SSL_C) */
#define MBEDTLS_SSL_CLI_C
/* MBEDTLS_SSL_SRV_C intentionally omitted */

#define MBEDTLS_SSL_PROTO_TLS1_2
#define MBEDTLS_SSL_PROTO_TLS1_3
/* MBEDTLS_SSL_PROTO_DTLS intentionally omitted (avoids timing.c dep) */

/* TLS 1.3: ephemeral key exchange only (no PSK) */
#define MBEDTLS_SSL_TLS1_3_KEY_EXCHANGE_MODE_EPHEMERAL_ENABLED
#define MBEDTLS_SSL_TLS1_3_KEY_EXCHANGE_MODE_PSK_EPHEMERAL_ENABLED

/* Required by current TLS 1.3 implementation */
#define MBEDTLS_SSL_KEEP_PEER_CERTIFICATE

/* Optional TLS features */
#define MBEDTLS_SSL_SERVER_NAME_INDICATION  /* SNI */
#define MBEDTLS_SSL_ALPN                    /* h2 / http1.1 */
#define MBEDTLS_SSL_SESSION_TICKETS         /* TLS 1.3 post-handshake messages */
#define MBEDTLS_SSL_ENCRYPT_THEN_MAC        /* PC-like TLS 1.2 compatibility ext */
#define MBEDTLS_SSL_EXTENDED_MASTER_SECRET  /* PC-like TLS 1.2 compatibility ext */
#define MBEDTLS_SSL_MAX_FRAGMENT_LENGTH

/* MBEDTLS_TIMING_C intentionally omitted (setitimer not available on 3DS) */
/* MBEDTLS_DEBUG_C intentionally omitted (saves code size) */

/* 3DS provides osGetTime() for ms timestamps; supply our own implementation */
#define MBEDTLS_PLATFORM_MS_TIME_ALT
