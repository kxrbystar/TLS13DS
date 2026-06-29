/* 3DS platform adaptations for mbedTLS 3.x:
 *   - Hardware entropy via sslcGenerateRandomData
 *   - Millisecond timer via osGetTime
 */
#include <3ds.h>
#include <stddef.h>
#include <stdint.h>

/* MBEDTLS_ENTROPY_HARDWARE_ALT */
int mbedtls_hardware_poll(void *data,
                           unsigned char *output, size_t len, size_t *olen)
{
    (void)data;
    sslcGenerateRandomData(output, len);
    if (olen) {
        *olen = len;
    }
    return 0;
}

/* MBEDTLS_PLATFORM_MS_TIME_ALT — milliseconds since boot */
typedef int64_t mbedtls_ms_time_t;
mbedtls_ms_time_t mbedtls_ms_time(void)
{
    return (mbedtls_ms_time_t)osGetTime();
}
